# frozen_string_literal: true

module ApexMail
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
end
