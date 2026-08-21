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
        Object replyTo,
        Object attachments,
        Object tags,
        String priority,
        Map<String, Object> metadata,
        String scheduledAt,
        String idempotencyKey
    ) {
        public SendRequest(
            Object from,
            Object to,
            String subject,
            String html,
            String text,
            String templateId,
            Object cc,
            Object bcc,
            Object replyTo,
            String scheduledAt,
            String idempotencyKey
        ) {
            this(from, to, subject, html, text, templateId, cc, bcc, replyTo, null, null, null, null, scheduledAt, idempotencyKey);
        }

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
            if (replyTo != null) {
                body.put("replyTo", replyTo);
            }
            if (attachments != null) {
                body.put("attachments", attachments);
            }
            if (tags != null) {
                body.put("tags", tags);
            }
            if (priority != null) {
                body.put("priority", priority);
            }
            if (metadata != null) {
                body.put("metadata", metadata);
            }
            if (scheduledAt != null) {
                body.put("scheduledAt", scheduledAt);
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
     * <p>When no {@code idempotencyKey} is supplied, a random UUID v4 is generated
     * per logical send and replayed across transport retries of that send, so
     * a retried POST can never enqueue the same message twice (SDK-B).
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
        String idempotencyKey = params.idempotencyKey();
        if (idempotencyKey == null || idempotencyKey.isBlank()) {
            idempotencyKey = java.util.UUID.randomUUID().toString();
        }
        return client.request("POST", "/v1/messages", body, SendResponse.class, idempotencyKey);
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
            params.get("replyTo"),
            params.get("attachments"),
            params.get("tags"),
            (String) params.get("priority"),
            castStringObjectMap(params.get("metadata")),
            (String) params.get("scheduledAt"),
            (String) params.get("idempotencyKey")
        ));
    }

    /** Cancel a scheduled email. */
    public GetResponse cancel(String id) {
        return client.request("POST", "/v1/messages/" + encode(id) + "/cancel", Map.of(), GetResponse.class);
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
        if (params.containsKey("replyTo")) {
            validateRecipients(params.get("replyTo"), "replyTo");
        }
    }

    /**
     * Send up to 1,000 emails in one API call.
     *
     * <p>An idempotency key is generated automatically and replayed across
     * transport retries of the batch call (SDK-B); supply {@code idempotencyKey}
     * via the overload to control it.
     *
     * @param messages  List of parameter maps (same shape as {@link #send})
     */
    public BatchResponse batch(List<Map<String, Object>> messages) {
        return batch(messages, null);
    }

    /**
     * Send up to 1,000 emails in one API call with an optional idempotency key.
     *
     * @param messages        List of parameter maps (same shape as {@link #send})
     * @param idempotencyKey  Caller-supplied idempotency key; a random UUID v4
     *                        is generated when null/blank (SDK-B)
     */
    public BatchResponse batch(List<Map<String, Object>> messages, String idempotencyKey) {
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
        String key = (idempotencyKey == null || idempotencyKey.isBlank())
            ? java.util.UUID.randomUUID().toString()
            : idempotencyKey;
        return client.request("POST", "/v1/messages/batch", Map.of("messages", messages), BatchResponse.class, key);
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
    private static Map<String, Object> castStringObjectMap(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> result = new HashMap<>();
            map.forEach((key, mapValue) -> result.put(String.valueOf(key), mapValue));
            return result;
        }
        throw new IllegalArgumentException("metadata must be a map");
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

    /**
     * Response from a single send. Real API shape (after envelope unwrap) is
     * the flat object {@code {"id": ..., "status": ..., "created_at": ...}}.
     */
    public record SendResponse(
        String id,
        String status,
        @com.fasterxml.jackson.annotation.JsonProperty("created_at") String createdAt,
        /** Deprecated: legacy nested shape; the live API never populates it. */
        Message message
    ) {
        public record Message(
            String id,
            String messageId,
            String status,
            Integer recipients,
            String scheduledAt,
            String createdAt
        ) {}
    }

    /**
     * Response from a batch send. Real API shape (after envelope unwrap) is
     * {@code {accepted, rejected, results: [{index, id?, status, error?}]}}.
     */
    public record BatchResponse(
        Integer accepted,
        Integer rejected,
        java.util.List<BatchItem> results,
        /** Deprecated: legacy nested shape; the live API never populates it. */
        Summary summary
    ) {
        /** One batch outcome: {index, id (accepted only), status, error (rejected only)}. */
        public record BatchItem(
            int index,
            String id,
            String status,
            String error,
            /** Deprecated legacy fields (never populated by the live API). */
            Boolean success,
            String messageId
        ) {}

        /** Deprecated legacy aggregate; the API returns accepted/rejected counts instead. */
        public record Summary(Integer total, Integer success, Integer failed) {}
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

    /**
     * SMTP delivery envelope with authentication results.
     *
     * <p>Returned as part of email detail and event responses.
     */
    public record Envelope(
        String from,
        java.util.List<String> to,
        String dkim,
        String spf,
        String dmarc,
        String timestamp
    ) {}

    public record GetResponse(EmailDetail message) {}

    public record ListResponse(java.util.List<EmailDetail> messages, Map<String, Object> pagination) {}
}
