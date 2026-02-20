package ee.apexmail.resources;

import ee.apexmail.ApexMailClient;

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
    public Map<String, Object> add(Object emails, String reason) {
        List<String> emailList = emails instanceof List<?>
            ? ((List<?>) emails).stream().map(Object::toString).toList()
            : List.of(emails.toString());
        return client.request("POST", "/v1/suppressions", Map.of(
            "emails", emailList,
            "reason", reason != null ? reason : "manual"
        ));
    }

    public Map<String, Object> add(String email) {
        return add(email, "manual");
    }

    /**
     * List suppressed addresses.
     *
     * @param options  Optional: {@code reason}, {@code limit}, {@code offset}
     */
    public Map<String, Object> list(Map<String, Object> options) {
        String q = options != null && !options.isEmpty()
            ? "?" + buildQuery(options) : "";
        return client.request("GET", "/v1/suppressions" + q, null);
    }

    public Map<String, Object> list() {
        return list(null);
    }

    /**
     * Check whether a specific address is suppressed.
     *
     * @return Response containing {@code suppressed: boolean}
     */
    public Map<String, Object> check(String email) {
        return client.request("GET",
            "/v1/suppressions/check?email=" + encode(email), null);
    }

    /**
     * Remove an address from the suppression list.
     *
     * <p>This only removes the internal suppression record; it does NOT
     * re-subscribe an end-user to marketing communications.
     */
    public Map<String, Object> delete(String email) {
        return client.request("DELETE", "/v1/suppressions/" + encode(email), null);
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
}
