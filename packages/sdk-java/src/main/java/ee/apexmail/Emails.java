package ee.apexmail;

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

    public record SendRequest(
        Object from,
        Object to,
        String subject,
        String html,
        String text,
        String templateId,
        Object cc,
        Object bcc,
        String idempotencyKey
    ) {
        Map<String, Object> toMap() {
            Map<String, Object> body = new HashMap<>();
            body.put("from", from);
            body.put("to", to);
            body.put("subject", subject);
            if (html != null) {
                body.put("html", html);
            }
            if (text != null) {
                body.put("text", text);
            }
            if (templateId != null) {
                body.put("templateId", templateId);
            }
            if (cc != null) {
                body.put("cc", cc);
            }
            if (bcc != null) {
                body.put("bcc", bcc);
            }
            return body;
        }
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
    public SendResponse send(SendRequest params) {
        if (params == null) {
            throw new IllegalArgumentException("params must not be null");
        }
        Map<String, Object> body = params.toMap();
        validateSendParams(body);
        return client.request("POST", "/v1/messages", body, SendResponse.class, params.idempotencyKey());
    }

    public SendResponse send(Map<String, Object> params) {
        if (params == null) {
            throw new IllegalArgumentException("params must not be null");
        }
        return send(new SendRequest(
            params.get("from"),
            params.get("to"),
            (String) params.get("subject"),
            (String) params.get("html"),
            (String) params.get("text"),
            (String) params.get("templateId"),
            params.get("cc"),
            params.get("bcc"),
            (String) params.get("idempotencyKey")
        ));
    }

    private static void validateSendParams(Map<String, Object> params) {
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
    }

    /**
     * Send up to 1,000 emails in one API call.
     *
     * @param messages  List of parameter maps (same shape as {@link #send})
     */
    public BatchResponse batch(List<Map<String, Object>> messages) {
        if (messages == null || messages.isEmpty()) {
            throw new IllegalArgumentException("messages must not be empty");
        }
        for (int i = 0; i < messages.size(); i++) {
            Map<String, Object> message = messages.get(i);
            if (message == null) {
                throw new IllegalArgumentException("message at index " + i + " must not be null");
            }
            validateRecipients(message.get("from"), "from");
            validateRecipients(message.get("to"), "to");
            if (message.containsKey("cc")) {
                validateRecipients(message.get("cc"), "cc");
            }
            if (message.containsKey("bcc")) {
                validateRecipients(message.get("bcc"), "bcc");
            }
            if (!message.containsKey("subject")) {
                throw new IllegalArgumentException("message at index " + i + " missing subject");
            }
            if (!message.containsKey("html") && !message.containsKey("text") && !message.containsKey("templateId")) {
                throw new IllegalArgumentException("message at index " + i + " missing html, text, or templateId");
            }
        }
        return client.request("POST", "/v1/messages/batch", Map.of("messages", messages), BatchResponse.class);
    }

    /** Get a sent email by its ID. */
    public GetResponse get(String id) {
        return client.request("GET", "/v1/messages/" + encode(id), null, GetResponse.class);
    }

    /**
     * List emails with optional filters.
     *
     * @param options  Optional filters: {@code status}, {@code limit}, {@code offset}, {@code tag}
     */
    public ListResponse list(Map<String, Object> options) {
        String query = buildQuery(options);
        return client.request("GET", "/v1/messages" + query, null, ListResponse.class);
    }

    public ListResponse list() {
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
            if (email == null || String.valueOf(email).isBlank()) {
                throw new IllegalArgumentException("Recipient object must include a non-empty 'email' field");
            }
            return String.valueOf(email);
        }
        return value == null ? null : String.valueOf(value);
    }

    private static void validateEmail(String email, String field) {
        if (email == null || !email.matches(EMAIL_REGEX)) {
            throw new IllegalArgumentException("Invalid " + field + " email format: " + email);
        }
    }

    public record SendResponse(Message message) {
        public record Message(
            String id,
            String messageId,
            String status,
            Integer recipients,
            String scheduledAt,
            String createdAt
        ) {}
    }

    public record BatchResponse(java.util.List<BatchItem> results, Summary summary) {
        public record BatchItem(
            int index,
            boolean success,
            String messageId,
            String error
        ) {}

        public record Summary(int total, int success, int failed) {}
    }

    public record EmailDetail(
        String id,
        String status,
        String fromEmail,
        String subject,
        java.util.List<String> tags,
        String createdAt,
        String sentAt,
        String deliveredAt,
        String openedAt,
        String clickedAt
    ) {}

    public record GetResponse(EmailDetail message) {}

    public record ListResponse(java.util.List<EmailDetail> messages, Map<String, Object> pagination) {}
}
