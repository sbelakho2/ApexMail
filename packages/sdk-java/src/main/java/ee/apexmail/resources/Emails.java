package ee.apexmail.resources;

import ee.apexmail.ApexMailClient;

import java.util.*;

/**
 * Send and manage transactional emails.
 *
 * <p>Access via {@code client.emails()}
 */
public final class Emails {

    private static final String EMAIL_REGEX = "^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$";

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
        if (params == null) {
            throw new IllegalArgumentException("params must not be null");
        }
        if (!params.containsKey("from")) {
            throw new IllegalArgumentException("from is required");
        }
        if (!params.containsKey("to")) {
            throw new IllegalArgumentException("to is required");
        }
        if (!params.containsKey("subject")) {
            throw new IllegalArgumentException("subject is required");
        }
        if (!params.containsKey("html") && !params.containsKey("text") && !params.containsKey("templateId")) {
            throw new IllegalArgumentException("html, text, or templateId is required");
        }

        validateRecipients(params.get("from"), "from");
        validateRecipients(params.get("to"), "to");
        if (params.containsKey("cc")) {
            validateRecipients(params.get("cc"), "cc");
        }
        if (params.containsKey("bcc")) {
            validateRecipients(params.get("bcc"), "bcc");
        }

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

    @SuppressWarnings("unchecked")
    private static void validateRecipients(Object value, String field) {
        if (value == null) {
            throw new IllegalArgumentException(field + " is required");
        }
        if (value instanceof Iterable<?>) {
            boolean hasAny = false;
            for (Object item : (Iterable<Object>) value) {
                hasAny = true;
                validateEmail(extractEmail(item), field);
            }
            if (!hasAny) {
                throw new IllegalArgumentException(field + " must include at least one recipient");
            }
            return;
        }
        validateEmail(extractEmail(value), field);
    }

    private static String extractEmail(Object value) {
        if (value instanceof Map<?, ?> map) {
            Object email = map.get("email");
            return email == null ? null : String.valueOf(email);
        }
        return value == null ? null : String.valueOf(value);
    }

    private static void validateEmail(String email, String field) {
        if (email == null || !email.matches(EMAIL_REGEX)) {
            throw new IllegalArgumentException("Invalid " + field + " email format: " + email);
        }
    }
}
