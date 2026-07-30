# frozen_string_literal: true

require "uri"

module ApexMail
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
        return
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

    # @param url    [String]
    # @param events [Array<String>] e.g. ["delivered", "bounced"]
    # @param secret [String, nil]
    def create(url:, events:, secret: nil)
      self.class.validate_webhook_url!(url)
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
      if params.key?(:url) && !params[:url].nil?
        self.class.validate_webhook_url!(params[:url])
      end
      @t.request("PUT", "/v1/webhooks/#{ApexMail.encode_path(id)}", body: params)
    end

    def delete(id)
      @t.request("DELETE", "/v1/webhooks/#{ApexMail.encode_path(id)}")
    end

    def test(id)
      @t.request("POST", "/v1/webhooks/#{ApexMail.encode_path(id)}/test")
    end

    # Atomically generate a new HMAC-SHA256 signing secret for a webhook endpoint.
    # The old secret is immediately invalidated. Requires the webhooks:write scope.
    def rotate_secret(id)
      @t.request("POST", "/v1/webhooks/#{ApexMail.encode_path(id)}/rotate-secret")
    end
  end
end
