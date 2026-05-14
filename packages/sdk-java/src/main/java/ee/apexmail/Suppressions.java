package ee.apexmail;

import com.fasterxml.jackson.core.type.TypeReference;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Manage the suppression list.
 *
 * <p>Access via {@code client.suppressions()}
 */
public final class Suppressions {

    private final ApexMailClient client;

    public Suppressions(ApexMailClient client) {
        this.client = client;
    }

    /**
     * Add a single email address to the suppression list.
     *
     * @param email  Email address to suppress
     * @param reason "unsubscribe" | "bounce" | "complaint" | "manual"
     */
    public Suppression add(String email, String reason) {
        return client.request("POST", "/v1/suppressions", Map.of(
            "emails", List.of(email),
            "reason", reason != null ? reason : "manual"
        ), Suppression.class);
    }

    /**
     * Add a single email address with default reason "manual".
     */
    public Suppression add(String email) {
        return add(email, "manual");
    }

    /**
     * Add multiple email addresses to the suppression list.
     *
     * @param emails List of email addresses
     * @param reason "unsubscribe" | "bounce" | "complaint" | "manual"
     */
    public Suppression addBulk(List<String> emails, String reason) {
        return client.request("POST", "/v1/suppressions", Map.of(
            "emails", emails,
            "reason", reason != null ? reason : "manual"
        ), Suppression.class);
    }

    /**
     * List suppressed addresses.
     *
     * @param options  Optional: {@code reason}, {@code limit}, {@code offset}
     */
    public SuppressionListResponse list(Map<String, Object> options) {
        String q = options != null && !options.isEmpty()
            ? "?" + buildQuery(options) : "";
        return client.request("GET", "/v1/suppressions" + q, null,
            SuppressionListResponse.class);
    }

    public SuppressionListResponse list() {
        return list(null);
    }

    /**
     * Check whether a specific address is suppressed.
     *
     * @return Response containing {@code suppressed: boolean}
     */
    public SuppressionCheckResponse check(String email) {
        return client.request("GET",
            "/v1/suppressions/check/" + encode(email), null,
            SuppressionCheckResponse.class);
    }

    /**
     * Remove an address from the suppression list.
     *
     * <p>This only removes the internal suppression record; it does NOT
     * re-subscribe an end-user to marketing communications.
     */
    public void delete(String email) {
        client.request("DELETE", "/v1/suppressions/" + encode(email), null, Void.class);
    }

    /** Add suppressions in bulk using the API's batch endpoint. */
    public Map<String, Object> bulk(Map<String, Object> params) {
        return client.request("POST", "/v1/suppressions/bulk", params, new TypeReference<Map<String, Object>>() {});
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

    public record Suppression(String email, String reason, String createdAt) {}

    public record SuppressionCheckResponse(boolean suppressed, String reason, String createdAt) {}

    public record SuppressionListResponse(java.util.List<Suppression> suppressions, Map<String, Object> pagination) {}
}
