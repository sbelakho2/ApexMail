package ee.apexmail;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Manage reusable email templates.
 *
 * <p>Access via {@code client.templates()}
 */
public final class Templates {

    private final ApexMailClient client;

    public Templates(ApexMailClient client) {
        this.client = client;
    }

    /**
     * Create a template.
     *
     * <p>Required: {@code name}, {@code subject}, {@code html}.
     * Optional: {@code engine}, {@code text}, {@code schema}.
     */
    public TemplateResponse create(Map<String, Object> params) {
        return client.request("POST", "/v1/templates", params, TemplateResponse.class);
    }

    /**
     * List templates.
     *
     * @param options  Optional: {@code limit}, {@code offset}
     */
    public TemplateListResponse list(Map<String, Object> options) {
        String q = options != null && !options.isEmpty()
            ? "?" + buildQuery(options) : "";
        return client.request("GET", "/v1/templates" + q, null, TemplateListResponse.class);
    }

    public TemplateListResponse list() {
        return list(null);
    }

    /** Get a template by ID. */
    public TemplateResponse get(String id) {
        return client.request("GET", "/v1/templates/" + encode(id), null, TemplateResponse.class);
    }

    /** Get a template by its unique slug. */
    public TemplateResponse getBySlug(String slug) {
        return client.request("GET", "/v1/templates/slug/" + encode(slug), null, TemplateResponse.class);
    }

    /** Update a template. A new version is created automatically. */
    public TemplateResponse update(String id, Map<String, Object> params) {
        return client.request("PUT", "/v1/templates/" + encode(id), params, TemplateResponse.class);
    }

    /** Delete a template and all its versions. */
    public void delete(String id) {
        client.request("DELETE", "/v1/templates/" + encode(id), null, Void.class);
    }

    /** Duplicate a template, creating a copy with a new ID. */
    public TemplateResponse duplicate(String id) {
        return client.request("POST", "/v1/templates/" + encode(id) + "/duplicate", null, TemplateResponse.class);
    }

    /**
     * Rollback a template to a previous version.
     *
     * @param id      Template ID
     * @param version The version number to roll back to
     */
    public TemplateResponse rollback(String id, int version) {
        return client.request("POST", "/v1/templates/" + encode(id) + "/rollback",
            Map.of("version", version), TemplateResponse.class);
    }

    /**
     * Render a template with given variables (dry-run — does not send).
     *
     * @param id    Template ID
     * @param data  Variable data map
     */
    public RenderResponse render(String id, Map<String, Object> data) {
        return client.request("POST", "/v1/templates/" + encode(id) + "/render",
            Map.of("variables", data != null ? data : Map.of()), RenderResponse.class);
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private static String encode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static String buildQuery(Map<String, Object> params) {
        StringBuilder sb = new StringBuilder();
        params.forEach((k, v) -> {
            if (v != null) {
                if (sb.length() > 0) sb.append('&');
                sb.append(encode(k)).append('=').append(encode(String.valueOf(v)));
            }
        });
        return sb.toString();
    }

    public record Template(
        String id,
        String name,
        String slug,
        String subject,
        String engine,
        Integer currentVersion,
        Boolean isActive,
        String createdAt,
        String updatedAt
    ) {}

    public record TemplateResponse(Template template) {}

    public record TemplateListResponse(java.util.List<Template> templates, Map<String, Object> pagination) {}

    public record RenderResponse(String html, String text, String subject) {}
}
