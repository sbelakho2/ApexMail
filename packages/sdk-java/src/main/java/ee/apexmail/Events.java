package ee.apexmail;

import com.fasterxml.jackson.core.type.TypeReference;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Query the email event log (delivery, opens, clicks, bounces, complaints, …).
 *
 * <p>Access via {@code client.events()}
 */
public final class Events {

    private final ApexMailClient client;

    public Events(ApexMailClient client) {
        this.client = client;
    }

    /**
     * List events with optional filters.
     *
     * <p>Supported filter keys: {@code type}, {@code messageId}, {@code domainId},
     * {@code start} (ISO 8601), {@code end} (ISO 8601), {@code limit}, {@code offset}.
     */
    public EventsListResponse list(Map<String, Object> options) {
        String q = options != null && !options.isEmpty()
            ? "?" + buildQuery(options) : "";
        return client.request("GET", "/v1/events" + q, null, EventsListResponse.class);
    }

    public EventsListResponse list() {
        return list(null);
    }

    /**
     * Get all events for a specific sent message (max 100 results).
     *
     * @param messageId  The email ID returned by {@code emails().send()}
     */
    public EventsListResponse getByMessage(String messageId) {
        return client.request("GET",
            "/v1/events?messageId=" + encode(messageId) + "&limit=100", null,
            EventsListResponse.class);
    }

    /**
     * Get a single event by ID.
     */
    public EventResponse get(String eventId) {
        return client.request("GET", "/v1/events/" + encode(eventId), null, EventResponse.class);
    }

    /** Return aggregate event counts with optional filters. */
    public Map<String, Object> stats(Map<String, Object> options) {
        String q = options != null && !options.isEmpty() ? "?" + buildQuery(options) : "";
        return client.request("GET", "/v1/events/stats" + q, null, new TypeReference<Map<String, Object>>() {});
    }

    public Map<String, Object> stats() {
        return stats(null);
    }

    /** Return event counts over time with optional filters. */
    public Map<String, Object> timeseries(Map<String, Object> options) {
        String q = options != null && !options.isEmpty() ? "?" + buildQuery(options) : "";
        return client.request("GET", "/v1/events/timeseries" + q, null, new TypeReference<Map<String, Object>>() {});
    }

    public Map<String, Object> timeseries() {
        return timeseries(null);
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

    public record Event(
        String id,
        String messageId,
        String eventType,
        String recipientEmail,
        String timestamp
    ) {}

    public record EventsListResponse(java.util.List<Event> events, Map<String, Object> pagination) {}

    public record EventResponse(Event event) {}
}
