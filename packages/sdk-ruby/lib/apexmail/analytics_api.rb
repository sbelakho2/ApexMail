# frozen_string_literal: true

module ApexMail
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
