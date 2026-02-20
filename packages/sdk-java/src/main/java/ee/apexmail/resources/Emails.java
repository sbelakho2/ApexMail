package ee.apexmail.resources;

import ee.apexmail.ApexMailClient;

import java.util.*;

/**
 * Send and manage transactional emails.
 *
 * <p>Access via {@code client.emails()}
 */
public final class Emails {

    private final ApexMailClient client;

    public Emails(ApexMailClient client) {
        this.client = client;
    }

    /**
     * Send a single email.
     *
     * <p>Required keys: {@code from}, {@code to}, {@code subject} plus at least one of
     * {@code html}, {@code text}, or {@code templateId}.
     *
     * @param params  Email parameters
     * @return API response including {@code id} of the queued message
     */
    public Map<String, Object> send(Map<String, Object> params) {
        Map<String, Object> body = new HashMap<>(params);
        String idempotencyKey = (String) body.remove("idempotencyKey");
        return client.request("POST", "/v1/messages", body, idempotencyKey);
    }

    /**
     * Send up to 1,000 emails in one API call.
     *
     * @param messages  List of parameter maps (same shape as {@link #send})
     */
    public Map<String, Object> batch(List<Map<String, Object>> messages) {
        return client.request("POST", "/v1/messages/batch", Map.of("messages", messages));
    }

    /** Get a sent email by its ID. */
    public Map<String, Object> get(String id) {
        return client.request("GET", "/v1/messages/" + encode(id), null);
    }

    /**
     * List emails with optional filters.
     *
     * @param options  Optional filters: {@code status}, {@code limit}, {@code offset}, {@code tag}
     */
    public Map<String, Object> list(Map<String, Object> options) {
        String query = buildQuery(options);
        return client.request("GET", "/v1/messages" + query, null);
    }

    public Map<String, Object> list() {
        return list(Map.of());
    }

    private static String encode(String s) {
        try {
            return java.net.URLEncoder.encode(s, "UTF-8");
        } catch (Exception e) {
            return s;
        }
    }

    private static String buildQuery(Map<String, Object> params) {
        if (params == null || params.isEmpty()) return "";
        StringJoiner sj = new StringJoiner("&", "?", "");
        sj.setEmptyValue("");
        params.forEach((k, v) -> {
            if (v != null) sj.add(encode(k) + "=" + encode(String.valueOf(v)));
        });
        String q = sj.toString();
        return q.equals("") ? "" : q;
    }
}
