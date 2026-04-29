package ee.apexmail;

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
     * Add one or more addresses to the suppression list.
     *
     * @param emails  Single address or list of addresses
     * @param reason  "unsubscribe" | "bounce" | "complaint" | "manual"
     */
    public Suppression add(Object emails, String reason) {
        List<String> emailList = emails instanceof List<?>
            ? ((List<?>) emails).stream().map(Object::toString).toList()
            : List.of(emails.toString());
        return client.request("POST", "/v1/suppressions", Map.of(
            "emails", emailList,
            "reason", reason != null ? reason : "manual"
        ), Suppression.class);
    }

    public Suppression add(String email) {
        return add(email, "manual");
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
