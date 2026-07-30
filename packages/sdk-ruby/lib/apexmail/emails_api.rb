# frozen_string_literal: true

require "uri"

module ApexMail
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

      template_id = options[:template_id] || options[:templateId]
      if (html.nil? || html.to_s.strip.empty?) && (text.nil? || text.to_s.strip.empty?) && template_id.nil?
        raise ArgumentError, 'Either "html", "text", or "template_id" body is required'
      end

      validate_recipients(from, 'from')
      validate_recipients(to, 'to')
      validate_recipients(options[:cc], 'cc') if options[:cc]
      validate_recipients(options[:bcc], 'bcc') if options[:bcc]

      idempotency_key = options.delete(:idempotency_key)
      body = {
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
      }.compact
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
      @t.request("POST", "/v1/messages/#{ApexMail.encode_path(id)}/cancel")
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
      params.merge(from: from, to: to).compact
    end

    def validate_send_params(params, index = nil)
      label = index.nil? ? 'message' : "message at index #{index}"
      from = params[:from] || params["from"]
      to = params[:to] || params["to"]
      subject = params[:subject] || params["subject"]
      html = params[:html] || params["html"]
      text = params[:text] || params["text"]
      # FIX-SDK-RUBY-001: Use symbol key :templateId (Ruby convention), not string key "templateId"
      template_id = params[:template_id] || params["template_id"] || params[:templateId]

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
  end
end
