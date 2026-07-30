# frozen_string_literal: true

module ApexMail
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
end
