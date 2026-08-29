package ee.apexmail;

import com.fasterxml.jackson.core.type.TypeReference;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * Manage webhook endpoint registrations.
 *
 * <p>Access via {@code client.webhooks()}
 */
public final class Webhooks {

    private final ApexMailClient client;

    public Webhooks(ApexMailClient client) {
        this.client = client;
    }

    /**
     * Event names the server accepts (webhooks.rs KNOWN_WEBHOOK_EVENTS) —
     * anything else is rejected with 422.
     */
    public static final List<String> KNOWN_WEBHOOK_EVENTS = List.of(
        "email.delivered",
        "email.bounced",
        "email.complained",
        "message.sent",
        "message.delivered",
        "message.bounced",
        "message.complained",
        "message.opened",
        "message.clicked",
        "recipient.unsubscribed",
        "placement_test.completed",
        "bounce",
        "complaint",
        "inbound",
        "*"
    );

    /**
     * Register a new webhook endpoint.
     *
     * <p>Only {@code url} and {@code events} are transmitted — the server's
     * CreateWebhookRequest uses deny_unknown_fields and the signing secret
     * is generated server-side (returned in the create response only).
     * Extra keys in {@code params} (name, secret, enabled, ...) are ignored
     * for backwards compatibility.
     *
     * @param params  Must include {@code url} and an {@code events} list
     *                with valid event names.
     */
    public Webhook create(Map<String, Object> params) {
        Object eventsRaw = params.get("events");
        if (!(eventsRaw instanceof List<?>)) {
            throw new IllegalArgumentException("events must be a list of event names");
        }
        List<?> events = (List<?>) eventsRaw;
        if (events.isEmpty()) {
            throw new IllegalArgumentException("events must include at least one event");
        }
        for (Object event : events) {
            if (!KNOWN_WEBHOOK_EVENTS.contains(String.valueOf(event))) {
                throw new IllegalArgumentException(
                    "Unknown webhook event type: " + event + ". Valid events: " + KNOWN_WEBHOOK_EVENTS);
            }
        }
        Map<String, Object> body = Map.of(
            "url", String.valueOf(params.get("url")),
            "events", events
        );
        return client.request("POST", "/v1/webhooks", body, Webhook.class);
    }

    /** Convenience overload for {@link #create(Map)}. */
    public Webhook create(String url, List<String> events) {
        return create(Map.of("url", url, "events", events));
    }

    /** List all registered webhooks (the API returns a bare array). */
    public List<Webhook> list() {
        return client.request("GET", "/v1/webhooks", null,
            new TypeReference<List<Webhook>>() {});
    }

    /** Get a webhook by its ID (flat WebhookResponse). */
    public Webhook get(String id) {
        return client.request("GET", "/v1/webhooks/" + encode(id), null, Webhook.class);
    }

    /**
     * Update a webhook (URL, events, or status).
     *
     * <p>Transmits only {url, events, status} per the server's
     * UpdateWebhookRequest (status one of "active" | "paused" |
     * "disabled"); a boolean {@code active} input is mapped to
     * active/paused for backwards compatibility, and unknown keys (name,
     * secret, enabled) are ignored.
     *
     * @param params  Optional: {@code url}, {@code events}, {@code status},
     *                legacy {@code active} (boolean)
     */
    public Webhook update(String id, Map<String, Object> params) {
        Map<String, Object> body = new java.util.LinkedHashMap<>();
        if (params.get("url") != null) {
            body.put("url", params.get("url"));
        }
        if (params.get("events") != null) {
            Object events = params.get("events");
            for (Object event : (List<?>) events) {
                if (!KNOWN_WEBHOOK_EVENTS.contains(String.valueOf(event))) {
                    throw new IllegalArgumentException(
                        "Unknown webhook event type: " + event + ". Valid events: " + KNOWN_WEBHOOK_EVENTS);
                }
            }
            body.put("events", events);
        }
        Object status = params.get("status");
        if (status == null && params.get("active") instanceof Boolean active) {
            status = active ? "active" : "paused";
        }
        if (status != null) {
            String statusText = String.valueOf(status);
            if (!List.of("active", "paused", "disabled").contains(statusText)) {
                throw new IllegalArgumentException(
                    "status must be one of active, paused, disabled (got " + statusText + ")");
            }
            body.put("status", statusText);
        }
        if (body.isEmpty()) {
            throw new IllegalArgumentException("Update payload must include at least one of url, events, status");
        }
        return client.request("PUT", "/v1/webhooks/" + encode(id), body, Webhook.class);
    }

    /** Delete a webhook endpoint. */
    public void delete(String id) {
        client.request("DELETE", "/v1/webhooks/" + encode(id), null, Void.class);
    }

    /**
     * Send a signed test event to a registered webhook endpoint (the
     * server takes no body). Returns {success, status_code?,
     * response_time_ms, error?}.
     */
    public Map<String, Object> test(String id) {
        return client.request("POST", "/v1/webhooks/" + encode(id) + "/test", null,
            new TypeReference<Map<String, Object>>() {});
    }

    /**
     * Rotate the webhook's signing secret (POST /:id/rotate-secret).
     * Returns the webhook with the new secret.
     */
    public Webhook rotateSecret(String id) {
        return client.request("POST", "/v1/webhooks/" + encode(id) + "/rotate-secret", null, Webhook.class);
    }

    private static String encode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    /**
     * The flat WebhookResponse: {id, url, events, secret (only at
     * creation/rotation), status, created_at, updated_at}. The API has no
     * name/enabled fields — status is "active" | "paused" | "disabled".
     */
    public record Webhook(
        String id,
        String url,
        List<String> events,
        String secret,
        String status,
        @com.fasterxml.jackson.annotation.JsonProperty("created_at") String createdAt,
        @com.fasterxml.jackson.annotation.JsonProperty("updated_at") String updatedAt
    ) {}
}
