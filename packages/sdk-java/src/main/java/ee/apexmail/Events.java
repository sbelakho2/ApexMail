package ee.apexmail;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Query the email event log (delivery, opens, clicks, bounces, complaints, …).
 *
 * <p>Access via {@code client.events()}
 *
 * <p>The server's ListEventsQuery (events.rs, deny_unknown_fields) accepts
 * exactly {@code limit}, {@code offset}, {@code event_type} and
 * {@code message_id} — verified against the live stack: any other query key
 * is answered with HTTP 400. The response is a bare array of event objects
 * ({@code id, message_id, event_type, recipient, metadata, timestamp}).
 */
public final class Events {

    private final ApexMailClient client;

    public Events(ApexMailClient client) {
        this.client = client;
    }

    /**
     * List events with optional filters.
     *
     * <p>Accepted keys: {@code event_type} (legacy alias {@code type}),
     * {@code message_id} (legacy alias {@code messageId}), {@code limit},
     * {@code offset}. The legacy {@code status}/{@code dateFrom}/
     * {@code dateTo}/{@code domainId}/{@code cursor} keys are NOT supported
     * by the server (HTTP 400) and are rejected client-side.
     */
    public List<Event> list(Map<String, Object> options) {
        return client.request("GET", "/v1/events" + buildFilterQuery(options), null,
            new com.fasterxml.jackson.core.type.TypeReference<List<Event>>() {});
    }

    public List<Event> list() {
        return list(null);
    }

    /**
     * Get all events for a specific sent message (max 100 results).
     *
     * @param messageId  The email ID returned by {@code emails().send()}
     */
    public List<Event> getByMessage(String messageId) {
        return client.request("GET",
            "/v1/events?message_id=" + encode(messageId) + "&limit=100", null,
            new com.fasterxml.jackson.core.type.TypeReference<List<Event>>() {});
    }

    /**
     * Get a single event by ID.
     */
    public Event get(String eventId) {
        return client.request("GET", "/v1/events/" + encode(eventId), null, Event.class);
    }

    /**
     * Aggregate event counts. The server's StatsQuery (deny_unknown_fields)
     * accepts {@code from} and {@code to} (ISO 8601) only.
     */
    public Map<String, Object> stats(Map<String, Object> options) {
        return client.request("GET", "/v1/events/stats" + buildStatsQuery(options), null,
            new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {});
    }

    public Map<String, Object> stats() {
        return stats(null);
    }

    /**
     * Event counts over time — a bare array of
     * {@code {timestamp, count, event_type}} buckets. Same filter contract
     * as {@link #stats(Map)}.
     */
    public List<Map<String, Object>> timeseries(Map<String, Object> options) {
        return client.request("GET", "/v1/events/timeseries" + buildStatsQuery(options), null,
            new com.fasterxml.jackson.core.type.TypeReference<List<Map<String, Object>>>() {});
    }

    public List<Map<String, Object>> timeseries() {
        return timeseries(null);
    }

    private static String buildFilterQuery(Map<String, Object> options) {
        if (options == null || options.isEmpty()) {
            return "";
        }
        for (String unsupported : List.of("status", "dateFrom", "dateTo", "date_from", "date_to",
            "domainId", "domain_id", "cursor")) {
            if (options.containsKey(unsupported)) {
                throw new IllegalArgumentException(
                    "GET /v1/events does not support '" + unsupported
                        + "' (the server ListEventsQuery accepts limit, offset, event_type, message_id only)");
            }
        }
        Map<String, Object> mapped = new LinkedHashMap<>();
        put(mapped, "event_type", firstNonNull(options.get("event_type"), options.get("type")));
        put(mapped, "message_id", firstNonNull(options.get("message_id"), options.get("messageId")));
        put(mapped, "limit", options.get("limit"));
        put(mapped, "offset", options.get("offset"));
        return buildQuery(mapped);
    }

    private static String buildStatsQuery(Map<String, Object> options) {
        if (options == null || options.isEmpty()) {
            return "";
        }
        for (String key : options.keySet()) {
            if (!List.of("from", "to", "start", "end").contains(key)) {
                throw new IllegalArgumentException(
                    "GET /v1/events/stats and /timeseries do not support '" + key
                        + "' (the server StatsQuery accepts from, to only)");
            }
        }
        Map<String, Object> mapped = new LinkedHashMap<>();
        put(mapped, "from", firstNonNull(options.get("from"), options.get("start")));
        put(mapped, "to", firstNonNull(options.get("to"), options.get("end")));
        return buildQuery(mapped);
    }

    private static void put(Map<String, Object> target, String key, Object value) {
        if (value != null) {
            target.put(key, value);
        }
    }

    private static Object firstNonNull(Object first, Object second) {
        return first != null ? first : second;
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
        return sb.length() == 0 ? "" : "?" + sb;
    }

    /**
     * One event — the live EventResponse shape
     * ({@code id, message_id, event_type, recipient, metadata, timestamp}).
     */
    public record Event(
        String id,
        @JsonProperty("message_id") String messageId,
        @JsonProperty("event_type") String eventType,
        @JsonProperty("recipient") String recipient,
        Map<String, Object> metadata,
        String timestamp
    ) {}

    /**
     * @deprecated The API returns a bare event array, never this wrapper
     *   (it only existed for a shape the server has never produced).
     *   {@link #list(Map)} and {@link #getByMessage(String)} return
     *   {@code List<Event>}.
     */
    @Deprecated
    public record EventsListResponse(List<Event> events, Map<String, Object> pagination) {}

    /**
     * @deprecated The API returns the flat event object, never an
     *   {@code {"event": ...}} wrapper. {@link #get(String)} returns
     *   {@link Event}.
     */
    @Deprecated
    public record EventResponse(Event event) {}
}
