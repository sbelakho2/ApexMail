package ee.apexmail;

import com.fasterxml.jackson.core.type.TypeReference;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
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
     * <p>Transmits exactly {name, subject, html_body, text_body?} per the
     * server's CreateTemplateRequest (deny_unknown_fields). Legacy keys
     * {@code html} / {@code text} are mapped; {@code slug}, {@code engine}
     * and {@code schema} inputs are ignored (the API has no such fields).
     *
     * <p>Required: {@code name}, {@code subject}, {@code html} (or
     * {@code html_body}).
     */
    public Template create(Map<String, Object> params) {
        Map<String, Object> body = new java.util.LinkedHashMap<>();
        putIfPresent(body, "name", params.get("name"));
        putIfPresent(body, "subject", params.get("subject"));
        putIfPresent(body, "html_body", firstNonNull(params.get("html_body"), params.get("html")));
        putIfPresent(body, "text_body", firstNonNull(params.get("text_body"), params.get("text")));
        if (body.size() < 3 || body.get("html_body") == null) {
            throw new IllegalArgumentException("name, subject, and html (html_body) are required");
        }
        return client.request("POST", "/v1/templates", body, Template.class);
    }

    /** List templates (the API returns a bare array). */
    public List<Template> list(Map<String, Object> options) {
        String q = options != null && !options.isEmpty()
            ? "?" + buildQuery(options) : "";
        return client.request("GET", "/v1/templates" + q, null,
            new TypeReference<List<Template>>() {});
    }

    public List<Template> list() {
        return list(null);
    }

    /** Get a template by ID (flat TemplateResponse). */
    public Template get(String id) {
        return client.request("GET", "/v1/templates/" + encode(id), null, Template.class);
    }

    /**
     * Update a template. A new version is created automatically.
     *
     * <p>Transmits only {name?, subject?, html_body?, text_body?} per the
     * server's UpdateTemplateRequest; legacy html/text keys are mapped and
     * unknown keys (engine, schema, slug) are ignored.
     */
    public Template update(String id, Map<String, Object> params) {
        Map<String, Object> body = new java.util.LinkedHashMap<>();
        putIfPresent(body, "name", params.get("name"));
        putIfPresent(body, "subject", params.get("subject"));
        putIfPresent(body, "html_body", firstNonNull(params.get("html_body"), params.get("html")));
        putIfPresent(body, "text_body", firstNonNull(params.get("text_body"), params.get("text")));
        if (body.isEmpty()) {
            throw new IllegalArgumentException("Update payload must include at least one field");
        }
        return client.request("PUT", "/v1/templates/" + encode(id), body, Template.class);
    }

    /** Delete a template and all its versions. */
    public void delete(String id) {
        client.request("DELETE", "/v1/templates/" + encode(id), null, Void.class);
    }

    /** Duplicate a template, creating a copy with a new ID. */
    public Template duplicate(String id) {
        return client.request("POST", "/v1/templates/" + encode(id) + "/duplicate", null, Template.class);
    }

    /**
     * Rollback a template to a previous version.
     *
     * @param id      Template ID
     * @param version The version number to roll back to
     */
    public Template rollback(String id, int version) {
        return client.request("POST", "/v1/templates/" + encode(id) + "/rollback",
            Map.of("version", version), Template.class);
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

    private static void putIfPresent(Map<String, Object> body, String key, Object value) {
        if (value != null) {
            body.put(key, value);
        }
    }

    private static Object firstNonNull(Object first, Object second) {
        return first != null ? first : second;
    }

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

    /**
     * The flat TemplateResponse: {id, name, subject, html_body, text_body,
     * version, status, created_at, updated_at}. The API has no slug or
     * engine fields and no by-slug route.
     */
    public record Template(
        String id,
        String name,
        String subject,
        @com.fasterxml.jackson.annotation.JsonProperty("html_body") String htmlBody,
        @com.fasterxml.jackson.annotation.JsonProperty("text_body") String textBody,
        int version,
        String status,
        @com.fasterxml.jackson.annotation.JsonProperty("created_at") String createdAt,
        @com.fasterxml.jackson.annotation.JsonProperty("updated_at") String updatedAt
    ) {}

    /** Rendered output ({subject, html, text?}). */
    public record RenderResponse(
        String subject,
        String html,
        String text
    ) {}
}
