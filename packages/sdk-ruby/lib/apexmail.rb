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
#   puts response[:id]

require "net/http"
require "uri"
require "json"
require "openssl"
require "securerandom"
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

  # Verify an ApexMail webhook signature in the platform's exact wire
  # format (worker-processors/src/webhook/processor.rs):
  #
  #   X-ApexMail-Signature: sha256=<hex hmac-sha256>
  #   X-ApexMail-Timestamp: <milliseconds since epoch>
  #   signed message: "{timestamp_millis}.{payload}"
  #
  # Pass BOTH platform headers via :timestamp_header (the raw
  # X-ApexMail-Timestamp value). Millisecond timestamps are auto-detected
  # (and compared against Time.now in milliseconds); the signed string
  # always uses the timestamp digits verbatim. The legacy combined header
  # form "t=<seconds>,v1=<hex>" and an explicit :timestamp override remain
  # supported.
  def self.verify_signature(payload, signature_header, secret, tolerance_seconds: 300,
                            timestamp: nil, timestamp_header: nil)
    raise ArgumentError, "payload must not be nil" if payload.nil?
    raise ArgumentError, "signature header must not be blank" if signature_header.to_s.empty?
    raise ArgumentError, "secret must not be blank" if secret.to_s.empty?

    parsed = parse_signature_header(signature_header.to_s)
    timestamp_text = timestamp || timestamp_header || parsed[:timestamp]
    signature = parsed[:signature]
    return false if timestamp_text.nil? || signature.to_s.empty?

    timestamp_text = timestamp_text.to_s.strip
    return false unless timestamp_text.match?(/\A\d+\z/)

    timestamp_int = timestamp_text.to_i
    milliseconds = timestamp_text.length > 11 || timestamp_int > 1_000_000_000_000
    now = milliseconds ? Time.now.to_f * 1000 : Time.now.to_i
    tolerance = milliseconds ? tolerance_seconds * 1000 : tolerance_seconds
    return false if (now - timestamp_int).abs > tolerance

    # Sign with the timestamp digits EXACTLY as delivered (milliseconds on
    # the platform path) — never a normalized form.
    signed_payload = "#{timestamp_text}.#{payload}"
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
    # Upper bound for the delay between retries. The server's Retry-After
    # header is honored in full up to this cap (SDK-F: was capped at
    # MAX_BACKOFF, silently truncating long rate-limit windows).
    MAX_RETRY_AFTER = 120.0

    # @param sleeper     [#call] Test seam: object called with the delay in
    #                            seconds instead of Kernel#sleep.
    # @param http_factory [#call] Test seam: returns an object that quacks like
    #                            Net::HTTP (start/request). Defaults to building
    #                            a fresh Net::HTTP per request (no shared
    #                            connection, so no cross-thread mutex needed).
    def initialize(api_key:, base_url:, open_timeout:, read_timeout:, max_response_bytes:,
                   sleeper: nil, http_factory: nil)
      @api_key      = api_key
      @base_uri     = URI.parse(base_url)
      raise ArgumentError, "baseUrl must use HTTPS" unless @base_uri.scheme == "https"
      @open_timeout = open_timeout
      @read_timeout = read_timeout
      @max_response_bytes = max_response_bytes
      @sleeper      = sleeper || ->(seconds) { sleep(seconds) }
      @http_factory = http_factory || method(:build_http)
    end

    def request(method, path, body: nil, idempotency_key: nil)
      # Duplicate-side-effect protection (SDK-B, matching the PHP SDK): a
      # POST that times out AFTER the server processed it retries blind —
      # creating a second webhook/template/API key. Every non-idempotent
      # request with a body gets a UUID generated BEFORE the retry loop, so
      # all attempts of the same logical operation present the same key.
      if idempotency_key.nil? && method.to_s.upcase == "POST" && body
        idempotency_key = SecureRandom.uuid
      end

      attempt = 0

      loop do
        begin
          # Fresh connection per request (SDK-G L11): a single shared
          # Net::HTTP guarded by a Mutex serialized all concurrent requests.
          http = @http_factory.call
          uri = URI.parse("#{@base_uri}#{path}")
          req = build_request(method, uri, body, idempotency_key)
          response_body = +""
          resp = http.start do |session|
            session.request(req) do |response|
              response.read_body do |chunk|
                response_body << chunk
                if response_body.bytesize > @max_response_bytes
                  raise Error.new("Response body exceeds max_response_bytes",
                                  status_code: response.code.to_i)
                end
              end
            end
          end

          if retryable_status?(resp.code.to_i) && attempt < MAX_RETRIES
            @sleeper.call(retry_delay(resp, attempt))
            attempt += 1
            next
          end

          return handle_response(resp, response_body)
        rescue IOError, EOFError, Timeout::Error, Errno::ECONNRESET, Errno::ECONNREFUSED, SocketError, OpenSSL::SSL::SSLError => e
          if attempt < MAX_RETRIES
            @sleeper.call(backoff(attempt))
            attempt += 1
            next
          end
          raise NetworkError, e.message
        end
      end
    end

    private

    def build_http
      http = Net::HTTP.new(@base_uri.host, @base_uri.port)
      http.use_ssl = @base_uri.scheme == "https"
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER if http.use_ssl?
      http.open_timeout = @open_timeout
      http.read_timeout = @read_timeout
      http
    end

    def build_request(method, uri, body, idempotency_key)
      klass = {
        "GET"    => Net::HTTP::Get,
        "POST"   => Net::HTTP::Post,
        "PUT"    => Net::HTTP::Put,
        "PATCH"  => Net::HTTP::Patch,
        "DELETE" => Net::HTTP::Delete,
      }.fetch(method.upcase) { raise ArgumentError, "Unsupported HTTP method: #{method}" }

      # Use the raw path (which may include a query string) — URI::HTTP no
      # longer exposes full_path/request_uri on modern Ruby versions.
      req = klass.new(uri.path.empty? ? "/" : "#{uri.path}#{uri.query ? "?#{uri.query}" : ''}")
      req["X-API-Key"]      = @api_key
      req["Content-Type"]    = "application/json"
      req["User-Agent"]      = "apexmail-ruby/#{SDK_VERSION}"
      if idempotency_key
        # Header injection: strip control bytes (CR/LF/NUL and friends) and
        # cap the length, like the PHP SDK does.
        safe_key = idempotency_key.gsub(/[\x00-\x1F\x7F]/, "")
        req["X-Idempotency-Key"] = safe_key[0, 128] unless safe_key.empty?
      end
      req.body = JSON.generate(body) if body
      req
    end

    def retryable_status?(status)
      status == 429 || status >= 500
    end

    # Delay before the next retry: max(quadratic backoff, Retry-After),
    # capped at MAX_RETRY_AFTER (120s).
    def retry_delay(resp, attempt)
      delay = backoff(attempt)
      retry_after = parse_retry_after(resp["Retry-After"])
      delay = retry_after if retry_after && retry_after > delay

      [delay, MAX_RETRY_AFTER].min
    end

    def parse_retry_after(value)
      return nil if value.nil? || value.empty?

      seconds = Integer(value, exception: false)
      return seconds.to_f if seconds

      begin
        date = Time.httpdate(value)
        [date - Time.now, 0].max
      rescue ArgumentError, TypeError
        nil
      end
    end

    # Quadratic backoff with jitter. attempt is the retry NUMBER about to
    # run (0 = first retry): the first retry uses attempt 1 — a 0-based
    # exponent produced a 0s delay (plus jitter only), an immediate hammer
    # at a server that had just said "slow down".
    def backoff(attempt)
      effective = attempt < 1 ? 1 : attempt
      delay = INITIAL_BACKOFF * (effective * effective)
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

      # SDK-G L9: the body may be a top-level JSON array (e.g. some list
      # endpoints); only treat it as an error envelope when it is a Hash.
      if parsed.is_a?(Hash)
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
        parsed = parsed[:data] if parsed.key?(:data)
      else
        message = body_text
        code = nil
        details = nil
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
      # SDK-A (critical): a non-JSON body (e.g. an HTML 502 page from a proxy)
      # must raise — previously it was rescued and returned as a success hash
      # like {raw:, parse_error:}.
      raise Error.new(
        "Invalid JSON response from API (HTTP #{resp.code}): #{e.message}",
        status_code: resp.code.to_i, code: "PARSE_ERROR",
        details: { raw_body: body_text[0, 500] }
      )
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
    # The serialized body matches the server's SendMessageRequest exactly
    # (messages.rs, deny_unknown_fields): from/to/cc/bcc go out as BARE
    # address strings ({email:, name:} hashes contribute only the address —
    # the API has no display-name field), tags as a string list, and
    # scheduled_at snake_case. Inputs the API rejects — reply_to,
    # template_id/template_data, attachments, priority — are accepted as
    # options for backwards compatibility but are NOT transmitted.
    #
    # @param from    [String, Hash]        Sender ("addr" or { email:, name: })
    # @param to      [String, Array<String, Hash>] Recipients
    # @param subject [String]
    # @param html    [String, nil]         HTML body
    # @param text    [String, nil]         Plain-text body
    # @param options [Hash]                Additional options
    # @option options [Array<String, Hash>] :cc
    # @option options [Array<String, Hash>] :bcc
    # @option options [Array<String, Hash>] :tags  (flattened to strings)
    # @option options [String]  :scheduled_at  ISO 8601 datetime (snake_case on the wire)
    # @option options [Hash]    :metadata
    # @option options [String]  :idempotency_key
    # @return [Hash] The API response: {id:, status:, created_at:}. An
    #   idempotency key is generated automatically when not supplied so that
    #   transport-level retries can never cause a duplicate send (SDK-B).
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

      # SDK-B: automatic idempotency key (caller-supplied key wins) so a
      # retried POST can never enqueue the same message twice.
      idempotency_key = options.delete(:idempotency_key) || SecureRandom.uuid
      body = build_send_payload(from: from, to: to, subject: subject, html: html, text: text, **options)
      @t.request("POST", "/v1/messages", body: body, idempotency_key: idempotency_key)
    end

    # Send up to 1,000 emails in one request.
    #
    # @param messages [Array<Hash>] Array of send parameters (same keys as #send)
    # @param idempotency_key [String, nil] Optional caller-supplied key; a
    #   random UUID is generated when omitted (SDK-B).
    # @return [Hash] The API response: {accepted:, rejected:, results: [{index,
    #   id?, status, error?}]}
    def batch(messages:, idempotency_key: nil)
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
      }, idempotency_key: idempotency_key || SecureRandom.uuid)
    end

    # Retrieve an email by ID.
    # @param id [String]
    def get(id)
      @t.request("GET", "/v1/messages/#{ApexMail.encode_path(id)}")
    end

    # List emails with optional filters. The server's ListMessagesQuery
    # accepts {limit, offset, cursor, status, sort_by} only — unknown query
    # parameters are rejected.
    # @param status [String, nil]
    # @param limit  [Integer]
    # @param offset [Integer]
    # @param cursor [String, nil]
    # @param sort_by [String, nil] ("created_at" | "updated_at" | "status" | "subject")
    def list(status: nil, limit: 20, offset: 0, cursor: nil, sort_by: nil)
      query = ApexMail.build_query(limit: limit, offset: offset, cursor: cursor, status: status, sort_by: sort_by)
      @t.request("GET", "/v1/messages#{query}")
    end

    # Cancel a queued or scheduled email by ID.
    # @param id [String] The message ID to cancel
    # @return [Hash] Queue cancellation result with +id+ and +status+ keys
    def cancel(id)
      @t.request("POST", "/v1/messages/#{ApexMail.encode_path(id)}/cancel")
    end

    private

    # Exact SendMessageRequest wire shape: bare address strings, string
    # tags, snake_case scheduled_at, and nothing the API would reject.
    def build_send_payload(from:, to:, subject:, html: nil, text: nil, **options)
      compact({
        from:         normalize_address(from),
        to:           normalize_recipients(to),
        cc:           normalize_recipients(options[:cc]),
        bcc:          normalize_recipients(options[:bcc]),
        subject:      subject,
        html:         html,
        text:         text,
        tags:         normalize_tags(options[:tags]),
        scheduled_at: options[:scheduled_at],
        metadata:     options[:metadata],
      })
    end

    # Extract the bare address string; the API has no display-name field.
    def normalize_address(addr)
      return nil if addr.nil?
      return addr[:email].to_s if addr.is_a?(Hash) && addr[:email]
      return addr["email"].to_s if addr.is_a?(Hash) && addr["email"]
      addr.to_s
    end

    # Recipients go out as a plain list of address strings — the API rejects
    # the historical {email:, name:} wrappers with 422.
    def normalize_recipients(recips)
      return nil if recips.nil?
      list = Array(recips).map { |recipient| normalize_address(recipient) }.compact
      list.empty? ? nil : list
    end

    # The API requires tags to be a Vec<String>; {name:, value:} hashes are
    # flattened to "name" or "name=value".
    def normalize_tags(tags)
      return nil if tags.nil?
      list = Array(tags).filter_map do |tag|
        if tag.is_a?(Hash) && tag[:name]
          tag[:value] ? "#{tag[:name]}=#{tag[:value]}" : tag[:name].to_s
        elsif tag.is_a?(Hash) && tag["name"]
          tag["value"] ? "#{tag["name"]}=#{tag["value"]}" : tag["name"].to_s
        else
          tag.to_s
        end
      end
      list.empty? ? nil : list
    end

    def validate_recipients(recips, field)
      # A single address spec {email:, name:} is ONE recipient — Array() on
      # a Hash expands it to key/value pairs, which would validate the
      # display name as an address.
      recips = [recips] if recips.is_a?(Hash)
      list = Array(recips)
      raise ArgumentError, "\"#{field}\" must include at least one recipient" if list.empty?

      list.each do |recipient|
        email = extract_email(recipient)
        unless email.is_a?(String) && EMAIL_REGEX.match?(email)
          raise ArgumentError, "Invalid \"#{field}\" email format: #{email}"
        end
      end
    end

    def extract_email(recipient)
      recipient.is_a?(Hash) ? recipient[:email] || recipient['email'] : recipient
    end

    def normalize_send_params(params)
      from = params[:from] || params["from"]
      to = params[:to] || params["to"]
      build_send_payload(
        from: from,
        to: to,
        subject: params[:subject] || params["subject"],
        html: params[:html] || params["html"],
        text: params[:text] || params["text"],
        cc: params[:cc] || params["cc"],
        bcc: params[:bcc] || params["bcc"],
        tags: params[:tags] || params["tags"],
        scheduled_at: params[:scheduled_at] || params[:scheduled_at] || params[:scheduledAt] || params["scheduledAt"],
        metadata: params[:metadata] || params["metadata"],
      )
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
      if (html.nil? || html.to_s.strip.empty?) && (text.nil? || text.to_s.strip.empty?)
        raise ArgumentError, template_id.nil? ?
          "#{label} missing html or text body" :
          "#{label} missing html or text body (template_id is not supported by the send API)"
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

    # Add a domain. The body sent is exactly {name: domain} per the API's
    # CreateDomainRequest (deny_unknown_fields).
    # @param domain [String]
    def create(domain:)
      @t.request("POST", "/v1/domains", body: { name: domain })
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

    # Get the health/verification state of a domain. The API has no
    # GET /:id/health endpoint — GET /:id itself returns the health
    # information (spf/dkim/dmarc/return_path booleans), so this is a thin
    # alias of #get.
    def health(id)
      get(id)
    end
  end

  # ── Webhooks ────────────────────────────────────────────────────────────────

  # Event names the server accepts (webhooks.rs KNOWN_WEBHOOK_EVENTS) —
  # anything else is rejected with 422.
  KNOWN_WEBHOOK_EVENTS = [
    "email.delivered",
    "email.bounced",
    "email.complained",
    "message.sent",
    "message.delivered",
    "message.bounced",
    "message.complained",
    "message.opened",
    "message.clicked",
    "recipient.unsubscribed",
    "placement_test.completed",
    "bounce",
    "complaint",
    "inbound",
    "*",
  ].freeze

  class WebhooksAPI
    def initialize(transport) = @t = transport

    # Validate that a webhook URL uses HTTPS (or localhost for development).
    #
    # @param url [String] the webhook URL to validate
    # @raise [ArgumentError] if the URL is not valid for webhook use
    def self.validate_webhook_url!(url)
      raise ArgumentError, "webhook URL must not be empty" if url.nil? || url.strip.empty?

      uri = URI.parse(url)
      case uri.scheme
      when "https"
        # Production: HTTPS is required
        nil
      when "http"
        # Development: HTTP allowed only for localhost/127.0.0.1/::1
        host = uri.host
        if host.nil? || !%w[localhost 127.0.0.1 ::1].include?(host)
          raise ArgumentError, "webhook URL must use HTTPS for non-localhost destinations (got: #{uri.scheme}://#{host})"
        end
      else
        raise ArgumentError, "webhook URL must use HTTPS (got: #{uri.scheme || 'nil'}://#{uri.host})"
      end
    rescue URI::InvalidURIError => e
      raise ArgumentError, "invalid webhook URL: #{url} (#{e.message})"
    end

    # Register a webhook. The body sent is exactly {url, events} per the
    # API's CreateWebhookRequest (deny_unknown_fields) — the signing secret
    # is generated server-side and returned in the create response only.
    #
    # @param url    [String]
    # @param events [Array<String>] valid names, e.g.
    #   ["message.delivered", "email.bounced", "*"] (see KNOWN_WEBHOOK_EVENTS)
    # @param secret [String, nil] Unused by the API (ignored; server-generated)
    def create(url:, events:, secret: nil)
      self.class.validate_webhook_url!(url)
      unknown = events.reject { |event| KNOWN_WEBHOOK_EVENTS.include?(event.to_s.strip) }
      unless unknown.empty?
        raise ArgumentError,
              "unknown webhook event type(s): #{unknown.join(', ')}; valid events: #{KNOWN_WEBHOOK_EVENTS.join(', ')}"
      end
      @t.request("POST", "/v1/webhooks", body: { url: url, events: events })
    end

    def list
      @t.request("GET", "/v1/webhooks")
    end

    def get(id)
      @t.request("GET", "/v1/webhooks/#{ApexMail.encode_path(id)}")
    end

    # Update a webhook. Transmits only {url, events, status} per the
    # API's UpdateWebhookRequest (status "active" | "paused" |
    # "disabled"); a boolean +active+ is mapped to active/paused for
    # backwards compatibility.
    #
    # @param id     [String]
    # @param url    [String, nil]
    # @param events [Array<String>, nil]
    # @param status [String, nil] "active" | "paused" | "disabled"
    # @param active [Boolean, nil] legacy: mapped to status
    def update(id, url: nil, events: nil, status: nil, active: nil, **_ignored)
      self.class.validate_webhook_url!(url) if url
      body = {}
      body[:url] = url if url
      if events
        unknown = events.reject { |event| KNOWN_WEBHOOK_EVENTS.include?(event.to_s.strip) }
        unless unknown.empty?
          raise ArgumentError,
                "unknown webhook event type(s): #{unknown.join(', ')}; valid events: #{KNOWN_WEBHOOK_EVENTS.join(', ')}"
        end
        body[:events] = events
      end
      status = (active ? "active" : "paused") if status.nil? && !active.nil?
      if status
        unless %w[active paused disabled].include?(status)
          raise ArgumentError, "status must be one of active, paused, disabled (got #{status.inspect})"
        end
        body[:status] = status
      end
      raise ArgumentError, "update requires at least one of url, events, status" if body.empty?

      @t.request("PUT", "/v1/webhooks/#{ApexMail.encode_path(id)}", body: body)
    end

    def delete(id)
      @t.request("DELETE", "/v1/webhooks/#{ApexMail.encode_path(id)}")
    end

    def test(id)
      @t.request("POST", "/v1/webhooks/#{ApexMail.encode_path(id)}/test")
    end

    # Rotate the webhook's signing secret; the response carries the new secret.
    def rotate_secret(id)
      @t.request("POST", "/v1/webhooks/#{ApexMail.encode_path(id)}/rotate-secret")
    end
  end

  # ── Templates ───────────────────────────────────────────────────────────────

  class TemplatesAPI
    def initialize(transport) = @t = transport

    # Create a template. The body sent is exactly
    # {name, subject, html_body, text_body?} per the API's
    # CreateTemplateRequest (deny_unknown_fields); +engine+ and extra opts
    # are accepted for backwards compatibility but NOT sent (the API has no
    # such fields).
    #
    # @param name    [String]
    # @param subject [String]
    # @param html    [String, nil] mapped to html_body
    # @param text    [String, nil] mapped to text_body
    def create(name:, subject:, html: nil, text: nil, **_ignored)
      @t.request("POST", "/v1/templates", body: {
        name: name, subject: subject, html_body: html, text_body: text,
      }.compact)
    end

    def list(limit: 50, offset: 0, cursor: nil)
      query = ApexMail.build_query(limit: limit, offset: offset, cursor: cursor)
      @t.request("GET", "/v1/templates#{query}")
    end

    def get(id)
      @t.request("GET", "/v1/templates/#{ApexMail.encode_path(id)}")
    end

    # Update a template (creates a new version automatically). Transmits
    # only {name?, subject?, html_body?, text_body?} per the API's
    # UpdateTemplateRequest; html/text keys are mapped and unknown keys
    # (engine, schema) are ignored.
    def update(id, name: nil, subject: nil, html: nil, text: nil, **_ignored)
      body = { name: name, subject: subject, html_body: html, text_body: text }.compact
      raise ArgumentError, "update requires at least one field" if body.empty?

      @t.request("PUT", "/v1/templates/#{ApexMail.encode_path(id)}", body: body)
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
    #
    # The API's CreateSuppressionRequest accepts exactly
    # {email: string, reason: string} for ONE address (deny_unknown_fields
    # — the historical emails[] body was rejected). A single address POSTs
    # once; multiple addresses use the /bulk endpoint with
    # {entries: [{email, reason}]}.
    #
    # @param emails [String, Array<String>] Single email or array of emails
    # @param reason [String] "bounce" | "complaint" | "unsubscribe" | "manual"
    def add(emails:, reason: "manual")
      email_list = Array(emails)
      if email_list.size <= 1
        return @t.request("POST", "/v1/suppressions", body: {
          email: email_list.first, reason: reason,
        })
      end

      bulk(entries: email_list.map { |email| { email: email, reason: reason } })
    end

    def list(limit: 50, offset: 0, cursor: nil, reason: nil)
      query = ApexMail.build_query(limit: limit, offset: offset, cursor: cursor, reason: reason)
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

    # Create an API key. Transmits exactly {name, scopes: [], expires_in_days?}
    # per the API's CreateApiKeyRequest (deny_unknown_fields); the legacy
    # expires_at input is ignored — use expires_in_days (1..365).
    def create(name:, scopes: [], expires_in_days: nil, expires_at: nil)
      body = { name: name, scopes: Array(scopes) }
      body[:expires_in_days] = expires_in_days if expires_in_days
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

  # Analytics subpath helpers. The analytics API has no GET /v1/analytics
  # endpoint — it exposes typed subpaths only, each accepting exactly
  # {from, to, interval} (interval: "hour" | "day" | "week" | "month").
  class AnalyticsAPI
    def initialize(transport) = @t = transport

    # Dashboard counters: {total_sent, total_delivered, total_bounced,
    # total_opened, total_clicked, delivery_rate, open_rate, click_rate}.
    def dashboard(from: nil, to: nil, interval: nil)
      @t.request("GET", "/v1/analytics/dashboard#{analytics_query(from, to, interval)}")
    end

    # Volume timeseries: [{date, sent, delivered, bounced}, ...].
    def volume(from: nil, to: nil, interval: nil)
      @t.request("GET", "/v1/analytics/volume#{analytics_query(from, to, interval)}")
    end

    # Engagement rates + timeseries: {open_rate, click_rate,
    # unsubscribe_rate, timeseries}.
    def engagement(from: nil, to: nil, interval: nil)
      @t.request("GET", "/v1/analytics/engagement#{analytics_query(from, to, interval)}")
    end

    # Deliverability rates: {delivery_rate, bounce_rate, complaint_rate,
    # inbox_rate}.
    def deliverability(from: nil, to: nil, interval: nil)
      @t.request("GET", "/v1/analytics/deliverability#{analytics_query(from, to, interval)}")
    end

    # Analyze a subject line (POST /subject-line with body {subject}).
    def analyze_subject_line(subject)
      @t.request("POST", "/v1/analytics/subject-line", body: { subject: subject })
    end

    # Start an analytics export job (GET /export with {from, to, format}).
    def export(from: nil, to: nil, format: "json")
      query = ApexMail.build_query(from: from, to: to, format: format)
      @t.request("GET", "/v1/analytics/export#{query}")
    end

    # Deprecated: GET /v1/analytics does not exist on the API. Kept as a
    # thin alias of #dashboard for backwards compatibility (+group_by+ is
    # mapped to interval; tag/domain are ignored).
    def get(from: nil, to: nil, group_by: nil, tag: nil, domain: nil)
      warn "AnalyticsAPI#get is deprecated; use dashboard/volume/engagement/deliverability"
      dashboard(from: from, to: to, interval: group_by)
    end

    private

    def analytics_query(from, to, interval)
      unless [nil, "hour", "day", "week", "month"].include?(interval)
        raise ArgumentError, "interval must be one of hour, day, week, month (got #{interval.inspect})"
      end

      ApexMail.build_query(from: from, to: to, interval: interval)
    end
  end
end
