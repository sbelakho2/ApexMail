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
        Object templateData,
        Object cc,
        Object bcc,
        Object replyTo,
        Object attachments,
        Object tags,
        Object priority,
        Map<String, String> headers,
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
            this(from, to, subject, html, text, templateId, null, cc, bcc, replyTo, null, null, null, null, null, scheduledAt, idempotencyKey);
        }

        /**
         * Serializes the send payload with every accepted option on the wire
         * (F48): from/to/cc/bcc/reply_to as address strings with display
         * names preserved as RFC 5322 {@code "Name <addr>"} forms, tags as
         * a string list, scheduled_at snake_case, and reply_to,
         * template_id/template_data, attachments, priority and headers
         * under their documented snake_case field names. Nothing the SDK
         * accepts is dropped silently.
         */
        Map<String, Object> toMap() {
            Map<String, Object> body = new HashMap<>();
            body.put("from", Emails.formatAddress(from));
            body.put("to", Emails.coerceAddressList(to));
            body.put("subject", subject);
            if (html != null) {
                body.put("html", html);
            }
            if (text != null) {
                body.put("text", text);
            }
            Object ccList = Emails.coerceAddressList(cc);
            if (ccList != null) {
                body.put("cc", ccList);
            }
            Object bccList = Emails.coerceAddressList(bcc);
            if (bccList != null) {
                body.put("bcc", bccList);
            }
            String replyToFormatted = Emails.formatAddress(replyTo);
            if (replyToFormatted != null) {
                body.put("reply_to", replyToFormatted);
            }
            if (templateId != null && !templateId.isBlank()) {
                body.put("template_id", templateId);
            }
            if (templateData != null) {
                body.put("template_data", templateData);
            }
            if (attachments != null) {
                body.put("attachments", attachments);
            }
            if (tags != null) {
                body.put("tags", Emails.coerceTagList(tags));
            }
            if (priority != null) {
                body.put("priority", Emails.normalizePriority(priority));
            }
            if (headers != null) {
                body.put("headers", headers);
            }
            if (metadata != null) {
                body.put("metadata", metadata);
            }
            if (scheduledAt != null) {
                body.put("scheduled_at", scheduledAt);
            }
            return body;
        }
    }

    /** Extracts the bare address string from "addr" or {email, name} inputs. */
    static String extractEmail(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Map<?, ?> map) {
            Object email = map.get("email");
            if (email == null) {
                email = map.get("address");
            }
            return email == null ? null : String.valueOf(email);
        }
        return bareAddress(String.valueOf(value));
    }

    /**
     * Strips an RFC 5322 display-name form to its bare address
     * ("Name &lt;a@b.c&gt;" → "a@b.c") so validation sees the addr-spec.
     */
    static String bareAddress(String value) {
        int open = value.lastIndexOf('<');
        int close = value.lastIndexOf('>');
        if (open >= 0 && close > open) {
            return value.substring(open + 1, close).trim();
        }
        return value;
    }

    /**
     * Serializes one address input, preserving the display name (F48):
     * {email, name} maps become {@code "Name <addr>"}; bare strings pass
     * through unchanged.
     */
    static String formatAddress(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Map<?, ?> map) {
            Object email = map.get("email");
            if (email == null) {
                email = map.get("address");
            }
            if (email == null) {
                return null;
            }
            Object name = map.get("name");
            if (name != null && !String.valueOf(name).isBlank()) {
                return name + " <" + email + ">";
            }
            return String.valueOf(email);
        }
        return String.valueOf(value);
    }

    /**
     * Coerces "addr" | ["addr", ...] | [{email, name}] to a List of address
     * strings, preserving display names as "Name <addr>" forms (F48).
     */
    static List<String> coerceAddressList(Object value) {
        if (value == null) {
            return null;
        }
        List<?> raw = value instanceof Iterable<?> iterable
            ? new java.util.ArrayList<>(java.util.stream.StreamSupport.stream(iterable.spliterator(), false).toList())
            : List.of(value);
        List<String> out = new java.util.ArrayList<>();
        for (Object item : raw) {
            String email = formatAddress(item);
            if (email != null && !email.isBlank()) {
                out.add(email);
            }
        }
        return out;
    }

    /** Flattens tags to a List<String> ("name" or "name=value" for map
     *  inputs) — the API requires Vec<String>. */
    static List<String> coerceTagList(Object tags) {
        List<String> out = new java.util.ArrayList<>();
        Iterable<?> raw = tags instanceof Iterable<?> iterable ? iterable : List.of(tags);
        for (Object tag : raw) {
            if (tag instanceof Map<?, ?> map && map.get("name") != null) {
                Object name = map.get("name");
                Object value = map.get("value");
                out.add(value == null ? String.valueOf(name) : name + "=" + value);
            } else if (tag != null) {
                out.add(String.valueOf(tag));
            }
        }
        return out;
    }

    /**
     * Normalizes/validates a priority input per the F48 shared contract
     * (packages/contract/send-contract.json): an integer 1-10 passes through
     * as an Integer, and the named levels "high"/"normal"/"low"
     * (case-insensitive) map to/passthrough as the canonical lowercase
     * strings the API deserializer maps to queue integers 7/5/3. Anything
     * else — including integers out of range and unknown strings — is an
     * IllegalArgumentException naming the contract, BEFORE the request
     * leaves the client.
     */
    static Object normalizePriority(Object priority) {
        String contract = "priority must be an integer between 1 and 10 or one of the named levels "
            + "\"high\"/\"normal\"/\"low\" (mapped to 7/5/3)";
        if (priority == null) {
            return null;
        }
        if (priority instanceof Integer || priority instanceof Long || priority instanceof Short || priority instanceof Byte) {
            int level = ((Number) priority).intValue();
            if (level < 1 || level > 10) {
                throw new IllegalArgumentException(contract + " — received the out-of-range integer " + level);
            }
            return level;
        }
        if (priority instanceof Number) {
            throw new IllegalArgumentException(contract + " — received the non-integer number " + priority);
        }
        if (priority instanceof Boolean) {
            throw new IllegalArgumentException(contract + " — received the boolean " + priority);
        }
        String level = String.valueOf(priority).trim();
        switch (level.toLowerCase(java.util.Locale.ROOT)) {
            case "high": return "high";
            case "normal": return "normal";
            case "low": return "low";
            default:
                throw new IllegalArgumentException(contract + " — received '" + level + "'");
        }
    }

    /**
     * Send a single email.
     *
     * <p>Required keys: {@code from}, {@code to}, {@code subject} plus at
     * least one of {@code html} or {@code text}.
     *
     * <p>Every accepted option is serialized (F48): from/to/cc/bcc/reply_to
     * go out as address strings with display names preserved as RFC 5322
     * {@code "Name <addr>"} forms ({email, name} map inputs keep their
     * name), tags as a string list, scheduled_at snake_case, and reply_to,
     * template_id/template_data, attachments, priority and headers under
     * their documented snake_case field names. Nothing the SDK accepts is
     * dropped silently.
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
            str(params, "templateId", "template_id"),
            params.containsKey("templateData") ? params.get("templateData") : params.get("template_data"),
            params.get("cc"),
            params.get("bcc"),
            params.containsKey("replyTo") ? params.get("replyTo") : params.get("reply_to"),
            params.get("attachments"),
            params.get("tags"),
            params.get("priority"),
            castStringMap(params.get("headers")),
            castStringObjectMap(params.get("metadata")),
            str(params, "scheduledAt", "scheduled_at"),
            str(params, "idempotencyKey", "idempotency_key")
        ));
    }

    private static String str(Map<String, Object> params, String... keys) {
        for (String key : keys) {
            Object value = params.get(key);
            if (value instanceof String s && !s.isBlank()) {
                return s;
            }
        }
        return null;
    }

    /**
     * Cancel a scheduled email. Returns the flat MessageResponse
     * ({id, status, created_at}).
     */
    public CancelResponse cancel(String id) {
        return client.request("POST", "/v1/messages/" + encode(id) + "/cancel", Map.of(), CancelResponse.class);
    }

    /** Flat cancellation result ({id, status, created_at}). */
    public record CancelResponse(
        String id,
        String status,
        @com.fasterxml.jackson.annotation.JsonProperty("created_at") String createdAt
    ) {}

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
        if (!params.containsKey("html") && !params.containsKey("text")) {
            if (params.containsKey("template_id")) {
                throw new IllegalArgumentException(
                    "html or text body is required (template_id alone cannot provide the body)");
            }
            throw new IllegalArgumentException("html or text is required");
        }

        validateRecipients(params.get("from"), "from");
        validateRecipients(params.get("to"), "to");
        if (params.containsKey("cc")) {
            validateRecipients(params.get("cc"), "cc");
        }
        if (params.containsKey("bcc")) {
            validateRecipients(params.get("bcc"), "bcc");
        }
        if (params.containsKey("reply_to")) {
            validateRecipients(params.get("reply_to"), "reply_to");
        }
    }

    /**
     * Normalize one batch message map with the same serialization as a
     * single send: display names preserved, every accepted option
     * (reply_to, template id/data, attachments, priority, headers) on the
     * wire (F48).
     */
    private static Map<String, Object> normalizeBatchMessage(Map<String, Object> message) {
        Map<String, Object> body = new HashMap<>();
        body.put("from", formatAddress(message.get("from")));
        body.put("to", coerceAddressList(message.get("to")));
        Object subject = message.get("subject");
        if (subject != null) {
            body.put("subject", subject);
        }
        if (message.get("html") != null) {
            body.put("html", message.get("html"));
        }
        if (message.get("text") != null) {
            body.put("text", message.get("text"));
        }
        Object ccList = coerceAddressList(message.get("cc"));
        if (ccList != null) {
            body.put("cc", ccList);
        }
        Object bccList = coerceAddressList(message.get("bcc"));
        if (bccList != null) {
            body.put("bcc", bccList);
        }
        String replyTo = formatAddress(first(message, "reply_to", "replyTo"));
        if (replyTo != null) {
            body.put("reply_to", replyTo);
        }
        String templateId = firstString(message, "template_id", "templateId");
        if (templateId != null && !templateId.isBlank()) {
            body.put("template_id", templateId);
        }
        Object templateData = first(message, "template_data", "templateData");
        if (templateData != null) {
            body.put("template_data", templateData);
        }
        if (message.get("attachments") != null) {
            body.put("attachments", message.get("attachments"));
        }
        if (message.get("tags") != null) {
            body.put("tags", coerceTagList(message.get("tags")));
        }
        Object priority = first(message, "priority");
        if (priority != null) {
            body.put("priority", normalizePriority(priority));
        }
        Object headers = first(message, "headers");
        if (headers != null) {
            body.put("headers", headers);
        }
        if (message.get("metadata") != null) {
            body.put("metadata", message.get("metadata"));
        }
        Object scheduledAt = message.get("scheduled_at");
        if (scheduledAt == null) {
            scheduledAt = message.get("scheduledAt");
        }
        if (scheduledAt != null) {
            body.put("scheduled_at", scheduledAt);
        }
        return body;
    }

    private static Object first(Map<String, Object> map, String... keys) {
        for (String key : keys) {
            if (map.containsKey(key)) {
                return map.get(key);
            }
        }
        return null;
    }

    private static String firstString(Map<String, Object> map, String... keys) {
        Object value = first(map, keys);
        return value == null ? null : String.valueOf(value);
    }

    /**
     * Send up to 1,000 emails in one API call.
     *
     * <p>An idempotency key is generated automatically and replayed across
     * transport retries of the batch call (SDK-B); supply {@code idempotencyKey}
     * via the overload to control it. Each message map is serialized with
     * the same serialization as {@link #send} (display names preserved,
     * snake_case scheduled_at, every accepted option forwarded — F48).
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
        List<Map<String, Object>> normalized = new java.util.ArrayList<>(messages.size());
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
            if (!message.containsKey("html") && !message.containsKey("text")) {
                if (message.containsKey("templateId") || message.containsKey("template_id")) {
                    throw new IllegalArgumentException("message at index " + i
                        + " missing html or text (template_id alone cannot provide the body)");
                }
                throw new IllegalArgumentException("message at index " + i + " missing html or text");
            }
            normalized.add(normalizeBatchMessage(message));
        }
        String key = (idempotencyKey == null || idempotencyKey.isBlank())
            ? java.util.UUID.randomUUID().toString()
            : idempotencyKey;
        return client.request("POST", "/v1/messages/batch", Map.of("messages", normalized), BatchResponse.class, key);
    }

    /**
     * Get a sent email by its ID — the flat MessageDetail payload
     * ({id, from, to, subject, status, tags, metadata, scheduled_at,
     * sent_at, created_at}); the API has no {"email": ...} wrapper.
     */
    public EmailDetail get(String id) {
        return client.request("GET", "/v1/messages/" + encode(id), null, EmailDetail.class);
    }

    /**
     * List emails with optional filters. The server's ListMessagesQuery
     * accepts {limit, offset, cursor, status, sort_by} only — after
     * envelope unwrap the payload is the bare MessageDetail array.
     *
     * @param options  Optional filters: {@code status}, {@code limit},
     *                 {@code offset}, {@code cursor}, {@code sort_by}
     * @return the bare list of message details
     */
    public List<EmailDetail> list(Map<String, Object> options) {
        String query = buildQuery(options);
        return client.request("GET", "/v1/messages" + query, null,
            new com.fasterxml.jackson.core.type.TypeReference<List<EmailDetail>>() {});
    }

    public List<EmailDetail> list() {
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
    private static Map<String, String> castStringMap(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Map<?, ?> map) {
            Map<String, String> result = new HashMap<>();
            map.forEach((key, mapValue) -> {
                if (key == null || mapValue == null) {
                    throw new IllegalArgumentException("headers must be a map of non-null strings");
                }
                result.put(String.valueOf(key), String.valueOf(mapValue));
            });
            return result;
        }
        throw new IllegalArgumentException("headers must be a map");
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
        String email = extractEmail(value);
        if (email == null) {
            throw new IllegalArgumentException("Recipient object must include a non-empty 'email' field");
        }
        validateEmail(email, field);
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

    /**
     * The flat MessageDetail payload of GET /v1/messages/:id: bare-string
     * from, string-array to, snake_case timestamps.
     */
    public record EmailDetail(
        String id,
        @com.fasterxml.jackson.annotation.JsonProperty("from") String from,
        java.util.List<String> to,
        String subject,
        String status,
        java.util.List<String> tags,
        Map<String, Object> metadata,
        @com.fasterxml.jackson.annotation.JsonProperty("scheduled_at") String scheduledAt,
        @com.fasterxml.jackson.annotation.JsonProperty("created_at") String createdAt,
        @com.fasterxml.jackson.annotation.JsonProperty("sent_at") String sentAt
    ) {}

    /**
     * Historical wrapper record.
     *
     * @deprecated the API returns the flat MessageDetail object (no
     * {"message": ...} wrapper); {@link #get(String)} returns
     * {@link EmailDetail} directly.
     */
    @Deprecated
    public record GetResponse(EmailDetail message) {}

    /**
     * Historical list response record.
     *
     * @deprecated the API returns the envelope {"data": [MessageDetail...],
     * "meta": ...}; {@link #list(Map)} returns the bare list.
     */
    @Deprecated
    public record ListResponse(java.util.List<EmailDetail> messages, Map<String, Object> pagination) {}

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

}