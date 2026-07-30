# frozen_string_literal: true

module ApexMail
  class EventsAPI
    def initialize(transport) = @t = transport

    # List events with optional filters.
    #
    # The server accepts (snake_case, strict): +limit+, +offset+, +cursor+,
    # +event_type+, +message_id+.
    #
    # Each event in the response may include an +envelope+ hash with:
    #   from::      [String, nil]  Envelope MAIL FROM address
    #   to::        [Array<String>] Envelope RCPT TO addresses
    #   dkim::      [String]  Authentication result: +pass+, +fail+, +neutral+, +none+
    #   spf::       [String]  Authentication result: +pass+, +fail+, +neutral+, +none+
    #   dmarc::     [String]  Authentication result: +pass+, +fail+, +neutral+, +none+
    #   timestamp:: [String]  ISO 8601 delivery event timestamp
    def list(message_id: nil, limit: 50, offset: 0, cursor: nil, event_type: nil)
      query = ApexMail.build_query(
        limit: limit, offset: offset, cursor: cursor,
        message_id: message_id, event_type: event_type
      )
      @t.request("GET", "/v1/events#{query}")
    end

    def get_by_message(message_id)
      query = ApexMail.build_query(message_id: message_id, limit: 100)
      @t.request("GET", "/v1/events#{query}")
    end

    # Get a single event by its ID.
    # @param event_id [String]
    def get(event_id)
      @t.request("GET", "/v1/events/#{ApexMail.encode_path(event_id)}")
    end

    # Event statistics for a date range (server requires +from+ / +to+).
    # @param from [String, Time, nil] inclusive start (ISO 8601)
    # @param to [String, Time, nil] inclusive end (ISO 8601)
    def stats(from: nil, to: nil)
      query = ApexMail.build_query(from: from, to: to)
      @t.request("GET", "/v1/events/stats#{query}")
    end

    # Event timeseries for a date range (server requires +from+ / +to+).
    # @param from [String, Time, nil] inclusive start (ISO 8601)
    # @param to [String, Time, nil] inclusive end (ISO 8601)
    def timeseries(from: nil, to: nil)
      query = ApexMail.build_query(from: from, to: to)
      @t.request("GET", "/v1/events/timeseries#{query}")
    end
  end
end
