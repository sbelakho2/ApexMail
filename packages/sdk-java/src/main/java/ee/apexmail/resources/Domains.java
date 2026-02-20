package ee.apexmail.resources;

import ee.apexmail.ApexMailClient;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Manage sending domains (SPF / DKIM / DMARC configuration and verification).
 *
 * <p>Access via {@code client.domains()}
 */
public final class Domains {

    private final ApexMailClient client;

    public Domains(ApexMailClient client) {
        this.client = client;
    }

    /**
     * Add a new sending domain to the account.
     *
     * @param domain   FQDN, e.g. {@code "mail.example.com"}
     * @param options  Optional: {@code region}, {@code clickTracking}, {@code openTracking}
     */
    public Map<String, Object> create(String domain, Map<String, Object> options) {
        Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("domain", domain);
        if (options != null) body.putAll(options);
        return client.request("POST", "/v1/domains", body);
    }

    public Map<String, Object> create(String domain) {
        return create(domain, null);
    }

    /** List all domains on the account. */
    public Map<String, Object> list() {
        return client.request("GET", "/v1/domains", null);
    }

    /** Get a domain by ID. */
    public Map<String, Object> get(String id) {
        return client.request("GET", "/v1/domains/" + encode(id), null);
    }

    /** Trigger DNS verification for a domain. */
    public Map<String, Object> verify(String id) {
        return client.request("POST", "/v1/domains/" + encode(id) + "/verify", Map.of());
    }

    /** Delete a domain (irreversible). */
    public Map<String, Object> delete(String id) {
        return client.request("DELETE", "/v1/domains/" + encode(id), null);
    }

    /** Check the deliverability health of a domain. */
    public Map<String, Object> health(String id) {
        return client.request("GET", "/v1/domains/" + encode(id) + "/health", null);
    }

    private static String encode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}
