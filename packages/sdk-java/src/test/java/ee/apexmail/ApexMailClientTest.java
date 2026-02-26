package ee.apexmail;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Comprehensive tests for the ApexMail Java SDK.
 * Uses JDK's built-in HttpServer for mocking since ApexMailClient is final.
 */
class ApexMailClientTest {

    // ── Test helpers ──────────────────────────────────────────────────────

    record Recorded(String method, String path, String body, Map<String, String> headers) {}

    /** Spin up a temporary HTTP server returning a fixed JSON response, recording the inbound request. */
    static Object[] mockServer(String responseJson, int statusCode) throws IOException {
        var recorded = new AtomicReference<Recorded>();
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/", exchange -> {
            byte[] reqBody = exchange.getRequestBody().readAllBytes();
            Map<String, String> hdrs = new HashMap<>();
            exchange.getRequestHeaders().forEach((k, v) -> hdrs.put(k.toLowerCase(), String.join(",", v)));
            recorded.set(new Recorded(
                exchange.getRequestMethod(),
                exchange.getRequestURI().toString(),
                new String(reqBody, StandardCharsets.UTF_8),
                hdrs
            ));
            byte[] resp = responseJson.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(statusCode, resp.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(resp); }
        });
        server.start();
        int port = server.getAddress().getPort();
        var client = new ApexMailClient("am_test_1234567890abcdef", "http://127.0.0.1:" + port);
        return new Object[]{ client, recorded, server };
    }

    static ApexMailClient client(Object[] arr) { return (ApexMailClient) arr[0]; }
    @SuppressWarnings("unchecked")
    static AtomicReference<Recorded> recorded(Object[] arr) { return (AtomicReference<Recorded>) arr[1]; }
    static HttpServer server(Object[] arr) { return (HttpServer) arr[2]; }
    static void stop(Object[] arr) { server(arr).stop(0); }

    // ── Emails ────────────────────────────────────────────────────────────

    @Nested
    class EmailTests {
        @Test
        void sendCallsPostMessages() throws Exception {
            var arr = mockServer("{\"message\":{\"id\":\"msg_1\",\"status\":\"queued\"}}", 200);
            try {
                var resp = client(arr).emails().send(Map.of(
                    "from", "a@b.c", "to", "x@y.z", "subject", "Hello", "html", "<p>hi</p>"
                ));
                assertEquals("POST", recorded(arr).get().method());
                assertEquals("/v1/messages", recorded(arr).get().path());
                assertEquals("msg_1", resp.message().id());
            } finally { stop(arr); }
        }

        @Test
        void sendForwardsIdempotencyKey() throws Exception {
            var arr = mockServer("{\"message\":{\"id\":\"msg_2\",\"status\":\"queued\"}}", 200);
            try {
                client(arr).emails().send(new HashMap<>(Map.of(
                    "from", "a@b.c", "to", "x@y.z", "subject", "Hi",
                    "idempotencyKey", "key-001"
                )));
                assertEquals("key-001", recorded(arr).get().headers().get("x-idempotency-key"));
            } finally { stop(arr); }
        }

        @Test
        void batchCallsPostBatch() throws Exception {
            var arr = mockServer("{\"results\":[{\"index\":0,\"success\":true,\"messageId\":\"m1\"}],\"summary\":{\"total\":1}}", 200);
            try {
                var resp = client(arr).emails().batch(List.of(
                    Map.of("from", "a@b.c", "to", "x@y.z", "subject", "msg 1")
                ));
                assertEquals("POST", recorded(arr).get().method());
                assertEquals("/v1/messages/batch", recorded(arr).get().path());
                assertEquals(1, resp.results().size());
            } finally { stop(arr); }
        }

        @Test
        void getCallsGetById() throws Exception {
            var arr = mockServer("{\"message\":{\"id\":\"msg_789\",\"status\":\"delivered\"}}", 200);
            try {
                var resp = client(arr).emails().get("msg_789");
                assertEquals("GET", recorded(arr).get().method());
                assertEquals("/v1/messages/msg_789", recorded(arr).get().path());
                assertEquals("msg_789", resp.message().id());
            } finally { stop(arr); }
        }

        @Test
        void listCallsGetMessages() throws Exception {
            var arr = mockServer("{\"messages\":[],\"pagination\":{\"total\":0}}", 200);
            try {
                client(arr).emails().list();
                assertEquals("GET", recorded(arr).get().method());
                assertTrue(recorded(arr).get().path().startsWith("/v1/messages"));
            } finally { stop(arr); }
        }
    }

    // ── Domains ───────────────────────────────────────────────────────────

    @Nested
    class DomainTests {
        @Test
        void createCallsPostDomains() throws Exception {
            var arr = mockServer("{\"domain\":{\"id\":\"dom_1\",\"domain\":\"mail.example.com\"}}", 200);
            try {
                var resp = client(arr).domains().create("mail.example.com");
                assertEquals("POST", recorded(arr).get().method());
                assertEquals("/v1/domains", recorded(arr).get().path());
                assertEquals("dom_1", resp.domain().id());
            } finally { stop(arr); }
        }

        @Test
        void listCallsGetDomains() throws Exception {
            var arr = mockServer("{\"domains\":[]}", 200);
            try {
                client(arr).domains().list();
                assertEquals("GET", recorded(arr).get().method());
                assertEquals("/v1/domains", recorded(arr).get().path());
            } finally { stop(arr); }
        }

        @Test
        void getCallsGetById() throws Exception {
            var arr = mockServer("{\"domain\":{\"id\":\"dom_1\"}}", 200);
            try {
                client(arr).domains().get("dom_1");
                assertEquals("GET", recorded(arr).get().method());
                assertEquals("/v1/domains/dom_1", recorded(arr).get().path());
            } finally { stop(arr); }
        }

        @Test
        void verifyCallsPostVerify() throws Exception {
            var arr = mockServer("{\"verified\":false,\"message\":\"DNS not propagated\"}", 200);
            try {
                var resp = client(arr).domains().verify("dom_1");
                assertEquals("POST", recorded(arr).get().method());
                assertEquals("/v1/domains/dom_1/verify", recorded(arr).get().path());
                assertEquals(false, resp.verified());
            } finally { stop(arr); }
        }

        @Test
        void deleteCallsDeleteById() throws Exception {
            var arr = mockServer("{}", 200);
            try {
                client(arr).domains().delete("dom_1");
                assertEquals("DELETE", recorded(arr).get().method());
                assertEquals("/v1/domains/dom_1", recorded(arr).get().path());
            } finally { stop(arr); }
        }

        @Test
        void healthCallsGetHealth() throws Exception {
            var arr = mockServer("{\"healthy\":true,\"spf\":\"pass\",\"dkim\":\"pass\"}", 200);
            try {
                var resp = client(arr).domains().health("dom_1");
                assertEquals("GET", recorded(arr).get().method());
                assertEquals("/v1/domains/dom_1/health", recorded(arr).get().path());
                assertEquals(true, resp.healthy());
            } finally { stop(arr); }
        }
    }

    // ── Webhooks ──────────────────────────────────────────────────────────

    @Nested
    class WebhookTests {
        @Test
        void createCallsPostWebhooks() throws Exception {
            var arr = mockServer("{\"webhook\":{\"id\":\"wh_1\",\"url\":\"https://ex.com/hook\"}}", 200);
            try {
                var resp = client(arr).webhooks().create(Map.of(
                    "url", "https://ex.com/hook", "events", List.of("email.delivered")
                ));
                assertEquals("POST", recorded(arr).get().method());
                assertEquals("/v1/webhooks", recorded(arr).get().path());
                assertEquals("wh_1", resp.webhook().id());
            } finally { stop(arr); }
        }

        @Test
        void listCallsGetWebhooks() throws Exception {
            var arr = mockServer("{\"webhooks\":[{\"id\":\"wh_1\"},{\"id\":\"wh_2\"}]}", 200);
            try {
                var resp = client(arr).webhooks().list();
                assertEquals("GET", recorded(arr).get().method());
                assertEquals("/v1/webhooks", recorded(arr).get().path());
                assertEquals(2, resp.webhooks().size());
            } finally { stop(arr); }
        }

        @Test
        void getCallsGetById() throws Exception {
            var arr = mockServer("{\"webhook\":{\"id\":\"wh_1\"}}", 200);
            try {
                var resp = client(arr).webhooks().get("wh_1");
                assertEquals("GET", recorded(arr).get().method());
                assertEquals("/v1/webhooks/wh_1", recorded(arr).get().path());
                assertEquals("wh_1", resp.webhook().id());
            } finally { stop(arr); }
        }

        @Test
        void updateCallsPatchById() throws Exception {
            var arr = mockServer("{\"webhook\":{\"id\":\"wh_1\",\"url\":\"https://new.com\"}}", 200);
            try {
                client(arr).webhooks().update("wh_1", Map.of("url", "https://new.com", "events", List.of("email.bounced")));
                assertEquals("PATCH", recorded(arr).get().method());
                assertEquals("/v1/webhooks/wh_1", recorded(arr).get().path());
            } finally { stop(arr); }
        }

        @Test
        void deleteCallsDeleteById() throws Exception {
            var arr = mockServer("{}", 200);
            try {
                client(arr).webhooks().delete("wh_1");
                assertEquals("DELETE", recorded(arr).get().method());
                assertEquals("/v1/webhooks/wh_1", recorded(arr).get().path());
            } finally { stop(arr); }
        }
    }

    // ── Templates ─────────────────────────────────────────────────────────

    @Nested
    class TemplateTests {
        @Test
        void createCallsPostTemplates() throws Exception {
            var arr = mockServer("{\"template\":{\"id\":\"tpl_1\",\"name\":\"Welcome\"}}", 200);
            try {
                var resp = client(arr).templates().create(Map.of("name", "Welcome", "subject", "Hi", "html", "<p>Hello</p>"));
                assertEquals("POST", recorded(arr).get().method());
                assertEquals("/v1/templates", recorded(arr).get().path());
                assertEquals("tpl_1", resp.template().id());
            } finally { stop(arr); }
        }

        @Test
        void getCallsGetById() throws Exception {
            var arr = mockServer("{\"template\":{\"id\":\"tpl_1\"}}", 200);
            try {
                client(arr).templates().get("tpl_1");
                assertEquals("GET", recorded(arr).get().method());
                assertEquals("/v1/templates/tpl_1", recorded(arr).get().path());
            } finally { stop(arr); }
        }

        @Test
        void getBySlugCallsGetBySlug() throws Exception {
            var arr = mockServer("{\"template\":{\"id\":\"tpl_1\",\"slug\":\"welcome\"}}", 200);
            try {
                var resp = client(arr).templates().getBySlug("welcome");
                assertEquals("GET", recorded(arr).get().method());
                assertEquals("/v1/templates/slug/welcome", recorded(arr).get().path());
                assertEquals("welcome", resp.template().slug());
            } finally { stop(arr); }
        }

        @Test
        void listCallsGetTemplates() throws Exception {
            var arr = mockServer("{\"templates\":[],\"pagination\":{\"total\":0}}", 200);
            try {
                client(arr).templates().list(Map.of("limit", 10));
                assertEquals("GET", recorded(arr).get().method());
                assertTrue(recorded(arr).get().path().startsWith("/v1/templates"));
                assertTrue(recorded(arr).get().path().contains("limit=10"));
            } finally { stop(arr); }
        }

        @Test
        void updateCallsPatchById() throws Exception {
            var arr = mockServer("{\"template\":{\"id\":\"tpl_1\",\"name\":\"Updated\"}}", 200);
            try {
                var resp = client(arr).templates().update("tpl_1", Map.of("name", "Updated"));
                assertEquals("PATCH", recorded(arr).get().method());
                assertEquals("/v1/templates/tpl_1", recorded(arr).get().path());
                assertEquals("Updated", resp.template().name());
            } finally { stop(arr); }
        }

        @Test
        void deleteCallsDeleteById() throws Exception {
            var arr = mockServer("{}", 200);
            try {
                client(arr).templates().delete("tpl_1");
                assertEquals("DELETE", recorded(arr).get().method());
                assertEquals("/v1/templates/tpl_1", recorded(arr).get().path());
            } finally { stop(arr); }
        }

        @Test
        void renderCallsPostRender() throws Exception {
            var arr = mockServer("{\"html\":\"<p>Hello Alice</p>\",\"text\":\"Hello Alice\"}", 200);
            try {
                var resp = client(arr).templates().render("tpl_1", Map.of("name", "Alice"));
                assertEquals("POST", recorded(arr).get().method());
                assertEquals("/v1/templates/tpl_1/render", recorded(arr).get().path());
                assertEquals("<p>Hello Alice</p>", resp.html());
            } finally { stop(arr); }
        }

        @Test
        void validateReactEmailCallsPost() throws Exception {
            var arr = mockServer("{\"valid\":true,\"errors\":[]}", 200);
            try {
                var resp = client(arr).templates().validateReactEmail("export default () => <h1>Hi</h1>");
                assertEquals("POST", recorded(arr).get().method());
                assertTrue(recorded(arr).get().path().contains("react-email/validate"));
                assertEquals(true, resp.valid());
            } finally { stop(arr); }
        }

        @Test
        void reactEmailStarterCallsGet() throws Exception {
            var arr = mockServer("{\"source\":\"import { Html } from ...\",\"name\":\"MyEmail\"}", 200);
            try {
                var resp = client(arr).templates().reactEmailStarter("MyEmail");
                assertEquals("GET", recorded(arr).get().method());
                assertTrue(recorded(arr).get().path().contains("react-email/starter"));
                assertTrue(recorded(arr).get().path().contains("name=MyEmail"));
                assertNotNull(resp.source());
            } finally { stop(arr); }
        }
    }

    // ── Suppressions ──────────────────────────────────────────────────────

    @Nested
    class SuppressionTests {
        @Test
        void addCallsPostSuppressions() throws Exception {
            var arr = mockServer("{}", 200);
            try {
                client(arr).suppressions().add("bad@example.com", "bounce");
                assertEquals("POST", recorded(arr).get().method());
                assertEquals("/v1/suppressions", recorded(arr).get().path());
                assertTrue(recorded(arr).get().body().contains("bad@example.com"));
                assertTrue(recorded(arr).get().body().contains("bounce"));
            } finally { stop(arr); }
        }

        @Test
        void addBulkSendsArray() throws Exception {
            var arr = mockServer("{}", 200);
            try {
                client(arr).suppressions().add(List.of("a@b.com", "c@d.com"), "manual");
                assertEquals("POST", recorded(arr).get().method());
                assertTrue(recorded(arr).get().body().contains("a@b.com"));
                assertTrue(recorded(arr).get().body().contains("c@d.com"));
            } finally { stop(arr); }
        }

        @Test
        void addDefaultsReasonToManual() throws Exception {
            var arr = mockServer("{}", 200);
            try {
                client(arr).suppressions().add("test@example.com");
                assertEquals("POST", recorded(arr).get().method());
                assertTrue(recorded(arr).get().body().contains("manual"));
            } finally { stop(arr); }
        }

        @Test
        void listCallsGetSuppressions() throws Exception {
            var arr = mockServer("{\"suppressions\":[],\"pagination\":{\"total\":0}}", 200);
            try {
                client(arr).suppressions().list(Map.of("reason", "bounce"));
                assertEquals("GET", recorded(arr).get().method());
                assertTrue(recorded(arr).get().path().startsWith("/v1/suppressions"));
                assertTrue(recorded(arr).get().path().contains("reason=bounce"));
            } finally { stop(arr); }
        }

        @Test
        void checkCallsGetCheck() throws Exception {
            var arr = mockServer("{\"suppressed\":true,\"reason\":\"bounce\"}", 200);
            try {
                var resp = client(arr).suppressions().check("bad@example.com");
                assertEquals("GET", recorded(arr).get().method());
                assertTrue(recorded(arr).get().path().contains("/v1/suppressions/check"));
                assertTrue(recorded(arr).get().path().contains("email=bad"));
                assertEquals(true, resp.suppressed());
            } finally { stop(arr); }
        }

        @Test
        void deleteCallsDeleteByEmail() throws Exception {
            var arr = mockServer("{}", 200);
            try {
                client(arr).suppressions().delete("bad@example.com");
                assertEquals("DELETE", recorded(arr).get().method());
                assertTrue(recorded(arr).get().path().contains("bad"));
            } finally { stop(arr); }
        }
    }

    // ── Events ────────────────────────────────────────────────────────────

    @Nested
    class EventTests {
        @Test
        void listCallsGetEvents() throws Exception {
            var arr = mockServer("{\"events\":[],\"pagination\":{\"total\":0}}", 200);
            try {
                client(arr).events().list(Map.of("messageId", "msg_123"));
                assertEquals("GET", recorded(arr).get().method());
                assertTrue(recorded(arr).get().path().startsWith("/v1/events"));
                assertTrue(recorded(arr).get().path().contains("messageId=msg_123"));
            } finally { stop(arr); }
        }

        @Test
        void getByMessageIncludesLimit100() throws Exception {
            var arr = mockServer("{\"events\":[{\"id\":\"evt_1\",\"type\":\"email.delivered\"}]}", 200);
            try {
                var resp = client(arr).events().getByMessage("msg_123");
                assertEquals("GET", recorded(arr).get().method());
                assertTrue(recorded(arr).get().path().contains("messageId=msg_123"));
                assertTrue(recorded(arr).get().path().contains("limit=100"));
                assertEquals(1, resp.events().size());
            } finally { stop(arr); }
        }

        @Test
        void getCallsGetById() throws Exception {
            var arr = mockServer("{\"event\":{\"id\":\"evt_42\",\"type\":\"email.opened\"}}", 200);
            try {
                var resp = client(arr).events().get("evt_42");
                assertEquals("GET", recorded(arr).get().method());
                assertEquals("/v1/events/evt_42", recorded(arr).get().path());
                assertEquals("evt_42", resp.event().id());
            } finally { stop(arr); }
        }
    }

    // ── Error handling ────────────────────────────────────────────────────

    @Nested
    class ErrorTests {
        @Test
        void authenticationExceptionOn401() throws Exception {
            var arr = mockServer("{\"error\":\"Invalid API key\"}", 401);
            try {
                assertThrows(AuthenticationException.class, () ->
                    client(arr).emails().send(Map.of("from", "a@b.c", "to", "x@y.z", "subject", "Hi"))
                );
            } finally { stop(arr); }
        }

        @Test
        void notFoundExceptionOn404() throws Exception {
            var arr = mockServer("{\"error\":\"Not found\"}", 404);
            try {
                assertThrows(NotFoundException.class, () -> client(arr).emails().get("nonexistent"));
            } finally { stop(arr); }
        }

        @Test
        void validationExceptionOn422() throws Exception {
            var arr = mockServer("{\"error\":\"Invalid params\",\"code\":\"validation_error\"}", 422);
            try {
                var ex = assertThrows(ValidationException.class, () ->
                    client(arr).emails().send(Map.of("from", "a@b.c", "to", "x@y.z", "subject", "Hi"))
                );
                assertEquals(422, ex.getStatusCode());
            } finally { stop(arr); }
        }

        @Test
        void rateLimitExceptionOn429() throws Exception {
            var arr = mockServer("{\"error\":\"Rate limit exceeded\"}", 429);
            try {
                assertThrows(RateLimitException.class, () ->
                    client(arr).emails().send(Map.of("from", "a@b.c", "to", "x@y.z", "subject", "Hi"))
                );
            } finally { stop(arr); }
        }

        @Test
        void baseExceptionOnUnmappedStatus() throws Exception {
            var arr = mockServer("{\"error\":\"Server error\"}", 500);
            try {
                assertThrows(ApexMailException.class, () -> client(arr).emails().get("x"));
            } finally { stop(arr); }
        }

        @Test
        void exceptionHasStatusCodeAndMessage() {
            var ex = new AuthenticationException("bad key", "auth_failed", 401);
            assertEquals(401, ex.getStatusCode());
            assertEquals("auth_failed", ex.getCode());
            assertTrue(ex.getMessage().contains("bad key"));
        }
    }

    // ── Client integration ────────────────────────────────────────────────

    @Nested
    class ClientTests {
        @Test
        void clientHasAllResourceApis() {
            var client = new ApexMailClient("test_key", "http://localhost:1");
            assertNotNull(client.emails());
            assertNotNull(client.domains());
            assertNotNull(client.webhooks());
            assertNotNull(client.templates());
            assertNotNull(client.suppressions());
            assertNotNull(client.events());
        }
    }
}
