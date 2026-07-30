# frozen_string_literal: true

require "net/http"
require "uri"
require "json"
require "openssl"
require "time"

module ApexMail
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
      req["Idempotency-Key"] = idempotency_key if idempotency_key
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
      raise ApexMail::Error.new(
        "Invalid JSON response from API (HTTP #{resp.code}): #{e.message}",
        status_code: resp.code.to_i, code: "PARSE_ERROR",
        details: { raw_body: body_text[0..500] }
      )
    end
  end
end
