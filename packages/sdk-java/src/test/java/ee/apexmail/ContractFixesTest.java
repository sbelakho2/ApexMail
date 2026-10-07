package ee.apexmail;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Live-contract regression tests for the 2026-10-06 dogfood SDK fixes.
 *
 * Every expectation was verified against the running api-server: the
 * events/api-keys response shapes (bare arrays), the server-side query
 * field names (deny_unknown_fields), the camelCase pagination meta, and the
 * `Idempotency-Key` header contract.
 */
class ContractFixesTest {

    private static ApexMailClient client(PayloadContractTest.RecordingHttpClient http) {
        return new ApexMailClient("am_test_0123456789abcdef", "https://api.apexmail.ee",
            Duration.ofSeconds(5), http);
    }

    // ── Idempotency header: the server reads Idempotency-Key ──────────────

    /** Request path + query as sent on the wire. */
    private static String pathOf(PayloadContractTest.RecordingHttpClient http) {
        java.net.URI uri = http.lastRequest().uri();
        return uri.getPath() + (uri.getQuery() != null ? "?" + uri.getQuery() : "");
    }


    @Test
    void sendUsesServerReadIdempotencyHeaderName() throws Exception {
        PayloadContractTest.RecordingHttpClient http =
            new PayloadContractTest.RecordingHttpClient(
                "{\"id\":\"m1\",\"status\":\"queued\",\"created_at\":\"now\"}");

        try (ApexMailClient client = client(http)) {
            client.emails().send(new Emails.SendRequest(
                "a@example.com", "b@example.com", "Hi", "<p>x</p>",
                null, null, null, null, null, null, null));

            assertTrue(http.lastRequest().headers().firstValue("Idempotency-Key").isPresent(),
                "server-read Idempotency-Key header must be present");
            assertTrue(http.lastRequest().headers().firstValue("X-Idempotency-Key").isEmpty(),
                "legacy X-Idempotency-Key must not be sent (the server ignores it)");
        }
    }

    // ── Events: real query names + real response shape ────────────────────

    @Test
    void eventsListSendsServerParamNamesAndParsesBareArray() throws Exception {
        PayloadContractTest.RecordingHttpClient http =
            new PayloadContractTest.RecordingHttpClient(
                "[{\"id\":\"evt_1\",\"message_id\":\"msg_1\",\"event_type\":\"message.delivered\","
                    + "\"recipient\":\"a@example.com\",\"metadata\":{},\"timestamp\":\"2026-10-04T18:46:57Z\"}]");

        try (ApexMailClient client = client(http)) {
            List<Events.Event> events = client.events().list(Map.of(
                "type", "message.delivered",
                "messageId", "msg_1",
                "limit", 5));

            assertTrue(pathOf(http).contains("event_type=message.delivered"),
                "unexpected path: " + pathOf(http));
            assertTrue(pathOf(http).contains("message_id=msg_1"),
                "unexpected path: " + pathOf(http));
            assertFalse(pathOf(http).contains("messageId"), "camelCase messageId is a server 400");

            assertEquals(1, events.size());
            assertEquals("evt_1", events.get(0).id());
            assertEquals("msg_1", events.get(0).messageId());
            assertEquals("message.delivered", events.get(0).eventType());
            assertEquals("a@example.com", events.get(0).recipient());
        }
    }

    @Test
    void eventsGetByMessageUsesMessageId() throws Exception {
        PayloadContractTest.RecordingHttpClient http =
            new PayloadContractTest.RecordingHttpClient("[]");

        try (ApexMailClient client = client(http)) {
            client.events().getByMessage("msg_abc");
            assertEquals("/v1/events?message_id=msg_abc&limit=100", pathOf(http));
        }
    }

    @Test
    void eventsListRejectsUnsupportedServerFilters() throws Exception {
        PayloadContractTest.RecordingHttpClient http =
            new PayloadContractTest.RecordingHttpClient("[]");

        try (ApexMailClient client = client(http)) {
            assertThrows(IllegalArgumentException.class,
                () -> client.events().list(Map.of("cursor", "abc")));
            assertThrows(IllegalArgumentException.class,
                () -> client.events().list(Map.of("status", "delivered")));
            assertThrows(IllegalArgumentException.class,
                () -> client.events().list(Map.of("domainId", "d1")));
        }
    }

    @Test
    void eventsTimeseriesParsesBareArrayAndStatsMapsFilters() throws Exception {
        // timeseries: bare array
        PayloadContractTest.RecordingHttpClient http =
            new PayloadContractTest.RecordingHttpClient(
                "[{\"timestamp\":\"2026-10-04T17:00:00Z\",\"count\":1,\"event_type\":\"bounced\"}]");
        try (ApexMailClient client = client(http)) {
            List<Map<String, Object>> points = client.events().timeseries(Map.of());
            assertEquals(1, points.size());
            assertEquals("bounced", points.get(0).get("event_type"));
            assertTrue(pathOf(http).startsWith("/v1/events/timeseries"), pathOf(http));
        }

        // stats: flat object; legacy start/end map to the server's from/to
        PayloadContractTest.RecordingHttpClient statsHttp =
            new PayloadContractTest.RecordingHttpClient(
                "{\"total\":7,\"delivered\":0,\"bounced\":3,\"complained\":0,\"opened\":1,\"clicked\":1}");
        try (ApexMailClient client = client(statsHttp)) {
            client.events().stats(Map.of("start", "2026-01-01T00:00:00Z", "to", "2026-01-02T00:00:00Z"));
            assertTrue(pathOf(statsHttp).startsWith("/v1/events/stats?from=2026-01-01"), pathOf(statsHttp));
            assertTrue(pathOf(statsHttp).contains("to=2026-01-02"), pathOf(statsHttp));

            assertThrows(IllegalArgumentException.class,
                () -> client.events().stats(Map.of("type", "message.delivered")));
        }
    }

    // ── API keys: bare-array list shape ───────────────────────────────────

    @Test
    void apiKeysListParsesBareArrayAndRejectsCursor() throws Exception {
        PayloadContractTest.RecordingHttpClient http =
            new PayloadContractTest.RecordingHttpClient(
                "[{\"id\":\"k1\",\"name\":\"deploy\",\"key_prefix\":\"am_live_…abcd\","
                    + "\"scopes\":[\"*\"],\"created_at\":\"t\",\"expires_at\":\"t\"}]");

        try (ApexMailClient client = client(http)) {
            List<Map<String, Object>> keys = client.apiKeys().list();
            assertEquals(1, keys.size());
            assertEquals("k1", keys.get(0).get("id"));
            assertTrue(pathOf(http).startsWith("/v1/auth/api-keys?"), pathOf(http));
            assertTrue(pathOf(http).contains("limit=50"), pathOf(http));
            assertTrue(pathOf(http).contains("offset=0"), pathOf(http));

            assertThrows(IllegalArgumentException.class,
                () -> client.apiKeys().list(Map.of("cursor", "abc")));
        }
    }

    // ── Pagination meta: camelCase keys, cleared when absent ──────────────

    @Test
    void paginationMetaIsExposedFromEnvelopeAndCleared() throws Exception {
        PayloadContractTest.RecordingHttpClient http =
            new PayloadContractTest.RecordingHttpClient(
                "{\"data\":[{\"id\":\"m1\",\"from\":\"a@example.com\",\"to\":[\"b@example.com\"],"
                    + "\"subject\":\"Hi\",\"status\":\"queued\",\"tags\":null,\"metadata\":null,"
                    + "\"scheduled_at\":null,\"created_at\":\"t\",\"sent_at\":null}],"
                    + "\"meta\":{\"hasMore\":true,\"nextCursor\":\"cur_abc123\"}}");

        try (ApexMailClient client = client(http)) {
            client.emails().list();
            Map<String, Object> meta = client.getLastResponseMeta().orElseThrow();
            assertEquals(true, meta.get("hasMore"));
            assertEquals("cur_abc123", meta.get("nextCursor"));
        }

        // A plain-array response (no envelope) must clear the previous meta.
        PayloadContractTest.RecordingHttpClient http2 =
            new PayloadContractTest.RecordingHttpClient("[]");
        try (ApexMailClient client = client(http2)) {
            client.emails().list();
            assertTrue(client.getLastResponseMeta().isEmpty(),
                "stale pagination meta must not survive a non-envelope response");
        }
    }
}
