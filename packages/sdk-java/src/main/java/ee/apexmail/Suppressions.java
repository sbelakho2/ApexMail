package ee.apexmail;

import com.fasterxml.jackson.core.type.TypeReference;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

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
     * <p>Transmits exactly {email, reason, source?} per the server's
     * CreateSuppressionRequest (deny_unknown_fields) — the historical
     * emails[] body was rejected by the API.
     *
     * @param email  Email address to suppress
     * @param reason "unsubscribe" | "bounce" | "complaint" | "manual"
     */
    public Suppression add(String email, String reason) {
        return client.request("POST", "/v1/suppressions", Map.of(
            "email", email,
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
     * Add multiple email addresses via the API's /bulk endpoint
     * ({entries: [{email, reason}]}).
     *
     * @param emails List of email addresses
     * @param reason "unsubscribe" | "bounce" | "complaint" | "manual"
     * @return {created, duplicates, invalid}
     */
    public BulkResponse addBulk(List<String> emails, String reason) {
        String effectiveReason = reason != null ? reason : "manual";
        List<Map<String, Object>> entries = new ArrayList<>(emails.size());
        for (String email : emails) {
            entries.add(Map.of("email", email, "reason", effectiveReason));
        }
        return client.request("POST", "/v1/suppressions/bulk", Map.of("entries", entries), BulkResponse.class);
    }

    /**
     * List suppressed addresses (the API returns a bare array).
     *
     * @param options  Optional: {@code reason}, {@code limit}, {@code offset}
     */
    public List<Suppression> list(Map<String, Object> options) {
        String q = options != null && !options.isEmpty()
            ? "?" + buildQuery(options) : "";
        return client.request("GET", "/v1/suppressions" + q, null,
            new TypeReference<List<Suppression>>() {});
    }

    public List<Suppression> list() {
        return list(null);
    }

    /**
     * Check whether a specific address is suppressed.
     *
     * @return {email, suppressed, reason?}
     */
    public CheckResponse check(String email) {
        return client.request("GET",
            "/v1/suppressions/check/" + encode(email), null,
            CheckResponse.class);
    }

    /**
     * Remove a suppression entry by its ID.
     *
     * <p>This only removes the internal suppression record; it does NOT
     * re-subscribe an end-user to marketing communications.
     *
     * @param id  The suppression entry ID
     */
    public void delete(String id) {
        client.request("DELETE", "/v1/suppressions/" + encode(id), null, Void.class);
    }

    /** Add suppressions in bulk with explicit entries ({email, reason}). */
    public BulkResponse bulk(List<Map<String, Object>> entries) {
        return client.request("POST", "/v1/suppressions/bulk", Map.of("entries", entries), BulkResponse.class);
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

    /** The flat SuppressionResponse: {id, email, reason, source, created_at}. */
    public record Suppression(
        String id,
        String email,
        String reason,
        String source,
        @com.fasterxml.jackson.annotation.JsonProperty("created_at") String createdAt
    ) {}

    /** The flat CheckResponse: {email, suppressed, reason?}. */
    public record CheckResponse(
        String email,
        boolean suppressed,
        String reason
    ) {}

    /** The flat BulkSuppressResponse: {created, duplicates, invalid}. */
    public record BulkResponse(int created, int duplicates, int invalid) {}
}
