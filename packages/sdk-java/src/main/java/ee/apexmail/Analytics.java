package ee.apexmail;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * Query aggregate email analytics.
 *
 * <p>The analytics API exposes typed subpaths only (there is no GET
 * /v1/analytics): /dashboard, /volume, /engagement, /deliverability,
 * /subject-line (POST) and /export. Every GET subpath accepts exactly the
 * query parameters {from, to, interval} (interval: hour | day | week |
 * month).
 */
public final class Analytics {
    private final ApexMailClient client;

    public Analytics(ApexMailClient client) {
        this.client = client;
    }

    /** Dashboard counters: {total_sent, total_delivered, total_bounced,
     *  total_opened, total_clicked, delivery_rate, open_rate, click_rate}. */
    public Map<String, Object> dashboard(String from, String to, String interval) {
        return client.request("GET", "/v1/analytics/dashboard" + analyticsQuery(from, to, interval),
            null, jsonMap());
    }

    /** Volume timeseries: [{date, sent, delivered, bounced}, ...]. */
    public Map<String, Object> volume(String from, String to, String interval) {
        return client.request("GET", "/v1/analytics/volume" + analyticsQuery(from, to, interval),
            null, jsonMap());
    }

    /** Engagement rates + timeseries: {open_rate, click_rate,
     *  unsubscribe_rate, timeseries}. */
    public Map<String, Object> engagement(String from, String to, String interval) {
        return client.request("GET", "/v1/analytics/engagement" + analyticsQuery(from, to, interval),
            null, jsonMap());
    }

    /** Deliverability rates: {delivery_rate, bounce_rate, complaint_rate, inbox_rate}. */
    public Map<String, Object> deliverability(String from, String to, String interval) {
        return client.request("GET", "/v1/analytics/deliverability" + analyticsQuery(from, to, interval),
            null, jsonMap());
    }

    /** Analyze a subject line (POST /subject-line with body {subject}). */
    public Map<String, Object> analyzeSubjectLine(String subject) {
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("subject is required");
        }
        return client.request("POST", "/v1/analytics/subject-line",
            Map.of("subject", subject), jsonMap());
    }

    /** Start an analytics export job (GET /export with {from, to, format}). */
    public Map<String, Object> export(String from, String to, String format) {
        StringBuilder query = new StringBuilder("?format=");
        query.append(encode(format == null || format.isBlank() ? "json" : format));
        if (from != null && !from.isBlank()) {
            query.append("&from=").append(encode(from));
        }
        if (to != null && !to.isBlank()) {
            query.append("&to=").append(encode(to));
        }
        return client.request("GET", "/v1/analytics/export" + query, null, jsonMap());
    }

    /**
     * Deprecated: GET /v1/analytics does not exist on the API. Kept as a
     * thin alias of {@link #dashboard} for backwards compatibility;
     * {@code groupBy} is mapped to interval, tag/domain are ignored.
     */
    @Deprecated
    public Map<String, Object> get(Map<String, Object> options) {
        if (options == null) {
            options = Map.of();
        }
        String interval = stringValue(firstNonNull(options.get("interval"), options.get("groupBy")));
        if (interval != null && !List.of("hour", "day", "week", "month").contains(interval)) {
            throw new IllegalArgumentException("interval must be one of hour, day, week, month (got " + interval + ")");
        }
        return dashboard(stringValue(options.get("from")), stringValue(options.get("to")), interval);
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private static com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>> jsonMap() {
        return new com.fasterxml.jackson.core.type.TypeReference<>() {};
    }

    private static String analyticsQuery(String from, String to, String interval) {
        if (interval != null && !interval.isBlank()
                && !List.of("hour", "day", "week", "month").contains(interval)) {
            throw new IllegalArgumentException("interval must be one of hour, day, week, month (got " + interval + ")");
        }
        StringBuilder query = new StringBuilder("?");
        boolean hasParam = false;
        if (from != null && !from.isBlank()) {
            query.append("from=").append(encode(from));
            hasParam = true;
        }
        if (to != null && !to.isBlank()) {
            if (hasParam) query.append('&');
            query.append("to=").append(encode(to));
            hasParam = true;
        }
        if (interval != null && !interval.isBlank()) {
            if (hasParam) query.append('&');
            query.append("interval=").append(encode(interval));
        }
        return query.toString();
    }

    private static Object firstNonNull(Object first, Object second) {
        return first != null ? first : second;
    }

    private static String stringValue(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    private static String encode(Object value) {
        return URLEncoder.encode(String.valueOf(value), StandardCharsets.UTF_8);
    }
}
