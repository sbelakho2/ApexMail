package ee.apexmail.resources;

import ee.apexmail.ApexMailClient;

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
     * <p>Required: {@code name}, {@code subject}, {@code html} (or {@code templateSource} for React).
     * Optional: {@code engine} ("handlebars" | "mjml" | "liquid" | "ejs" | "react"),
     * {@code text}, {@code schema}.
     */
    public Map<String, Object> create(Map<String, Object> params) {
        return client.request("POST", "/v1/templates", params);
    }

    /**
     * List templates.
     *
     * @param options  Optional: {@code limit}, {@code offset}
     */
    public Map<String, Object> list(Map<String, Object> options) {
        String q = options != null && !options.isEmpty()
            ? "?" + buildQuery(options) : "";
        return client.request("GET", "/v1/templates" + q, null);
    }

    public Map<String, Object> list() {
        return list(null);
    }

    /** Get a template by ID. */
    public Map<String, Object> get(String id) {
        return client.request("GET", "/v1/templates/" + encode(id), null);
    }

    /** Get a template by its unique slug. */
    public Map<String, Object> getBySlug(String slug) {
        return client.request("GET", "/v1/templates/slug/" + encode(slug), null);
    }

    /** Update a template. A new version is created automatically. */
    public Map<String, Object> update(String id, Map<String, Object> params) {
        return client.request("PATCH", "/v1/templates/" + encode(id), params);
    }

    /** Delete a template and all its versions. */
    public Map<String, Object> delete(String id) {
        return client.request("DELETE", "/v1/templates/" + encode(id), null);
    }

    /**
     * Render a template with given data (dry-run — does not send).
     *
     * @param id    Template ID
     * @param data  Variable data map
     */
    public Map<String, Object> render(String id, Map<String, Object> data) {
        return client.request("POST", "/v1/templates/" + encode(id) + "/render",
            Map.of("data", data != null ? data : Map.of()));
    }

    /**
     * Validate a React Email JSX source string.
     *
     * @param source  Raw JSX source
     */
    public Map<String, Object> validateReactEmail(String source) {
        return client.request("POST", "/v1/templates/react-email/validate", Map.of("source", source));
    }

    /**
     * Retrieve a React Email JSX starter template.
     *
     * @param componentName  Name for the root React component
     */
    public Map<String, Object> reactEmailStarter(String componentName) {
        return client.request("GET",
            "/v1/templates/react-email/starter?name=" + encode(componentName), null);
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
}
