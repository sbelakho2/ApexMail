package ee.apexmail;

import com.fasterxml.jackson.core.type.TypeReference;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
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
     * <p>Transmits exactly {name} per the server's CreateDomainRequest
     * (deny_unknown_fields); legacy options (region, clickTracking,
     * openTracking) are ignored.
     *
     * @param domain   FQDN, e.g. {@code "mail.example.com"}
     * @param options  Ignored legacy options
     */
    public Domain create(String domain, Map<String, Object> options) {
        return client.request("POST", "/v1/domains", Map.of("name", domain), Domain.class);
    }

    public Domain create(String domain) {
        return create(domain, null);
    }

    /** List all domains on the account (the API returns a bare array). */
    public List<Domain> list() {
        return client.request("GET", "/v1/domains", null, new TypeReference<List<Domain>>() {});
    }

    /** Get a domain by ID (flat DomainResponse). */
    public Domain get(String id) {
        return client.request("GET", "/v1/domains/" + encode(id), null, Domain.class);
    }

    /** Trigger DNS verification for a domain ({domain, spf_verified,
     *  dkim_verified, dmarc_verified, return_path_verified, status}). */
    public VerifyResponse verify(String id) {
        return client.request("POST", "/v1/domains/" + encode(id) + "/verify", null, VerifyResponse.class);
    }

    /** Delete a domain (irreversible). */
    public void delete(String id) {
        client.request("DELETE", "/v1/domains/" + encode(id), null, Void.class);
    }

    /**
     * Check the deliverability health of a domain.
     *
     * <p>The API has no GET /:id/health endpoint — GET /:id itself returns
     * the health information (spf/dkim/dmarc/return_path verification
     * booleans plus status), so this is a thin alias of {@link #get}.
     */
    public Domain health(String id) {
        return get(id);
    }

    private static String encode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    /**
     * The flat DomainResponse: {id, name, status, ses_verified,
     * spf_verified, dkim_verified, dmarc_verified, return_path_verified,
     * created_at}.
     */
    public record Domain(
        String id,
        String name,
        String status,
        @com.fasterxml.jackson.annotation.JsonProperty("ses_verified") boolean sesVerified,
        @com.fasterxml.jackson.annotation.JsonProperty("spf_verified") boolean spfVerified,
        @com.fasterxml.jackson.annotation.JsonProperty("dkim_verified") boolean dkimVerified,
        @com.fasterxml.jackson.annotation.JsonProperty("dmarc_verified") boolean dmarcVerified,
        @com.fasterxml.jackson.annotation.JsonProperty("return_path_verified") boolean returnPathVerified,
        @com.fasterxml.jackson.annotation.JsonProperty("created_at") String createdAt
    ) {}

    /** DNS record for verification ({record_type, hostname, value, priority?}). */
    public record DNSRecord(
        @com.fasterxml.jackson.annotation.JsonProperty("record_type") String recordType,
        String hostname,
        String value,
        Integer priority
    ) {}

    /** Verification result (verify endpoint). */
    public record VerifyResponse(
        String domain,
        @com.fasterxml.jackson.annotation.JsonProperty("spf_verified") boolean spfVerified,
        @com.fasterxml.jackson.annotation.JsonProperty("dkim_verified") boolean dkimVerified,
        @com.fasterxml.jackson.annotation.JsonProperty("dmarc_verified") boolean dmarcVerified,
        @com.fasterxml.jackson.annotation.JsonProperty("return_path_verified") boolean returnPathVerified,
        String status
    ) {}
}
