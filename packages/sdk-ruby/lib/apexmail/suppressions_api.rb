# frozen_string_literal: true

module ApexMail
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
end
