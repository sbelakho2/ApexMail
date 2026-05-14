package ee.apexmail;

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
    public CreateResponse create(String domain, Map<String, Object> options) {
        Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("domain", domain);
        if (options != null) body.putAll(options);
        return client.request("POST", "/v1/domains", body, CreateResponse.class);
    }

    public CreateResponse create(String domain) {
        return create(domain, null);
    }

    /** List all domains on the account. */
    public ListResponse list() {
        return client.request("GET", "/v1/domains", null, ListResponse.class);
    }

    /** Get a domain by ID. */
    public GetResponse get(String id) {
        return client.request("GET", "/v1/domains/" + encode(id), null, GetResponse.class);
    }

    /** Trigger DNS verification for a domain. */
    public VerifyResponse verify(String id) {
        return client.request("POST", "/v1/domains/" + encode(id) + "/verify", Map.of(), VerifyResponse.class);
    }

    /** Delete a domain (irreversible). */
    public void delete(String id) {
        client.request("DELETE", "/v1/domains/" + encode(id), null, Void.class);
    }

    /** Check the deliverability health of a domain. */
    public HealthResponse health(String id) {
        return client.request("GET", "/v1/domains/" + encode(id) + "/health", null, HealthResponse.class);
    }

    private static String encode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    public record Domain(
        String id,
        String domain,
        String status,
        String healthStatus,
        String createdAt,
        String updatedAt
    ) {}

    public record DNSRecord(
        String recordType,
        String hostname,
        String value,
        Integer priority
    ) {}

    public record CreateResponse(Domain domain, java.util.List<DNSRecord> dnsRecords) {}

    public record GetResponse(Domain domain) {}

    public record ListResponse(java.util.List<Domain> domains, Map<String, Object> pagination) {}

    public record VerifyResponse(boolean verified, String message) {}

    public record HealthResponse(String spf, String dkim, String dmarc, String blacklist, boolean healthy) {}
}
