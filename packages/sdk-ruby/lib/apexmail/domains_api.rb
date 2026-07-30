# frozen_string_literal: true

module ApexMail
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
end
