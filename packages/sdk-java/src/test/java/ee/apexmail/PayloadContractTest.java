package ee.apexmail;

import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.io.IOException;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.Flow;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Payload contract tests: the wire bodies this SDK emits must match the
 * server DTOs in api-server/src/routes/*.rs exactly (most use
 * serde(deny_unknown_fields), so any extra key is a 422), plus the
 * platform webhook-signature format.
 */
class PayloadContractTest {

    // ── F1: send wire shape vs messages.rs SendMessageRequest ─────────────

    @Test
    void typedSendSerializesExactServerShape() throws Exception {
        RecordingHttpClient http = new RecordingHttpClient(flatSendResponse());
        try (ApexMailClient client = client(http)) {
            Emails.SendResponse response = client.emails().send(new Emails.SendRequest(
                "hello@example.com",
                List.of("user@example.com", Map.of("email", "second@example.com", "name", "Dropped")),
                "Hello!",
                "<h1>Hello World</h1>",
                null,
                "tpl_legacy",               // must NOT be sent
                List.of("cc@example.com"),
                List.of("bcc@example.com"),
                "reply@example.com",         // must NOT be sent
                null,
                List.of("welcome"),
                "high",                      // must NOT be sent
                Map.of("source", "java-sdk-test"),
                "2026-09-01T09:00:00Z",
                null
            ));

            assertEquals("msg_1", response.id());
            Map<String, Object> body = http.lastRequestBodyJson();

            assertEquals("hello@example.com", body.get("from"));
            assertEquals(List.of("user@example.com", "second@example.com"), body.get("to"));
            assertEquals(List.of("cc@example.com"), body.get("cc"));
            assertEquals(List.of("bcc@example.com"), body.get("bcc"));
            assertEquals(List.of("welcome"), body.get("tags"));
            assertEquals("2026-09-01T09:00:00Z", body.get("scheduled_at"));

            for (String forbidden : new String[]{
                "replyTo", "templateId", "templateData", "attachments", "priority", "scheduledAt", "name"}) {
                assertFalse(body.containsKey(forbidden), forbidden + " must not be serialized");
            }
        }
    }

    @Test
    void mapSendCoercesBareStringToAndDropsUnknownFields() throws Exception {
        RecordingHttpClient http = new RecordingHttpClient(flatSendResponse());
        try (ApexMailClient client = client(http)) {
            Map<String, Object> params = new HashMap<>();
            params.put("from", Map.of("email", "named@example.com", "name", "Named"));
            params.put("to", "user@example.com"); // bare string — coerced to a list
            params.put("subject", "Hi");
            params.put("text", "Hello");
            params.put("replyTo", "r@example.com");
            params.put("priority", "high");

            client.emails().send(params);

            Map<String, Object> body = http.lastRequestBodyJson();
            assertEquals("named@example.com", body.get("from"));
            assertEquals(List.of("user@example.com"), body.get("to"));
            assertFalse(body.containsKey("replyTo"));
            assertFalse(body.containsKey("priority"));
        }
    }

    @Test
    void batchNormalizesEachMessageLikeSend() throws Exception {
        RecordingHttpClient http = new RecordingHttpClient(
            "{\"accepted\":1,\"rejected\":0,\"results\":[{\"index\":0,\"id\":\"m\",\"status\":\"queued\"}]}");
        try (ApexMailClient client = client(http)) {
            Map<String, Object> message = new HashMap<>();
            message.put("from", "hello@example.com");
            message.put("to", "user@example.com");
            message.put("subject", "Hi");
            message.put("text", "Hello");
            message.put("scheduledAt", "2026-09-01T09:00:00Z");

            client.emails().batch(List.of(message));

            Map<String, Object> body = http.lastRequestBodyJson();
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> messages = (List<Map<String, Object>>) body.get("messages");
            assertEquals(1, messages.size());
            assertEquals(List.of("user@example.com"), messages.get(0).get("to"));
            assertEquals("hello@example.com", messages.get(0).get("from"));
            assertEquals("2026-09-01T09:00:00Z", messages.get(0).get("scheduled_at"));
            assertFalse(messages.get(0).containsKey("scheduledAt"));
        }
    }

    // ── F2: webhook wire shapes vs webhooks.rs ────────────────────────────

    @Test
    void webhookCreateSendsExactlyUrlAndEventsAndParsesFlatResponse() throws Exception {
        String flatWebhook = "{\"id\":\"wh_1\",\"url\":\"https://example.com/hook\","
            + "\"events\":[\"message.delivered\"],\"secret\":\"whsec_server\",\"status\":\"active\","
            + "\"created_at\":\"t\",\"updated_at\":\"t\"}";
        RecordingHttpClient http = new RecordingHttpClient(flatWebhook);
        try (ApexMailClient client = client(http)) {
            Webhooks.Webhook webhook = client.webhooks().create(Map.of(
                "url", "https://example.com/hook",
                "events", List.of("message.delivered", "*"),
                "secret", "whsec_legacy",   // must NOT be sent
                "name", "legacy",           // must NOT be sent
                "enabled", true             // must NOT be sent
            ));

            assertEquals("/v1/webhooks", http.lastPath);
            Map<String, Object> body = http.lastRequestBodyJson();
            assertEquals(2, body.size());
            assertEquals("https://example.com/hook", body.get("url"));
            assertEquals(List.of("message.delivered", "*"), body.get("events"));

            assertEquals("wh_1", webhook.id());
            assertEquals("active", webhook.status());
            assertEquals("whsec_server", webhook.secret());
        }
    }

    @Test
    void webhookUpdateMapsActiveToStatusAndRejectsUnknownEvents() throws Exception {
        RecordingHttpClient http = new RecordingHttpClient(
            "{\"id\":\"wh_1\",\"url\":\"https://example.com/hook\",\"events\":[\"message.opened\"],"
                + "\"status\":\"paused\",\"created_at\":\"t\",\"updated_at\":\"t\"}");
        try (ApexMailClient client = client(http)) {
            Map<String, Object> params = new HashMap<>();
            params.put("events", List.of("message.opened"));
            params.put("active", false);
            params.put("secret", "nope");

            Webhooks.Webhook webhook = client.webhooks().update("wh_1", params);
            assertEquals("paused", webhook.status());

            Map<String, Object> body = http.lastRequestBodyJson();
            assertEquals("paused", body.get("status"));
            assertFalse(body.containsKey("active"));
            assertFalse(body.containsKey("secret"));

            // Unknown event names must be rejected client-side (422 server-side).
            boolean rejected = false;
            try {
                client.webhooks().update("wh_1", Map.of("events", List.of("delivered")));
            } catch (IllegalArgumentException expected) {
                rejected = true;
            }
            assertTrue(rejected, "unknown event name must be rejected");
        }
    }

    @Test
    void knownWebhookEventsMatchServerList() {
        assertEquals(
            List.of("email.delivered", "email.bounced", "email.complained",
                "message.sent", "message.delivered", "message.bounced",
                "message.complained", "message.opened", "message.clicked",
                "recipient.unsubscribed", "placement_test.completed",
                "bounce", "complaint", "inbound", "*"),
            Webhooks.KNOWN_WEBHOOK_EVENTS);
    }

    // ── F4: template wire shape vs templates.rs ───────────────────────────

    @Test
    void templateCreateMapsHtmlToHtmlBody() throws Exception {
        RecordingHttpClient http = new RecordingHttpClient(
            "{\"id\":\"tpl_1\",\"name\":\"welcome\",\"subject\":\"Welcome!\",\"html_body\":\"<p>Hi</p>\","
                + "\"version\":1,\"status\":\"active\",\"created_at\":\"t\",\"updated_at\":\"t\"}");
        try (ApexMailClient client = client(http)) {
            Templates.Template template = client.templates().create(Map.of(
                "name", "welcome",
                "subject", "Welcome!",
                "html", "<p>Hi</p>",
                "slug", "welcome-v1",       // must NOT be sent
                "engine", "handlebars"      // must NOT be sent
            ));

            Map<String, Object> body = http.lastRequestBodyJson();
            assertEquals(3, body.size());
            assertEquals("<p>Hi</p>", body.get("html_body"));
            assertFalse(body.containsKey("html"));
            assertFalse(body.containsKey("slug"));
            assertFalse(body.containsKey("engine"));

            assertEquals("<p>Hi</p>", template.htmlBody());
            assertEquals(1, template.version());
        }
    }

    // ── F5: suppression wire shape vs suppressions.rs ─────────────────────

    @Test
    void suppressionAddSendsSingleEmailBody() throws Exception {
        RecordingHttpClient http = new RecordingHttpClient(
            "{\"id\":\"sup_1\",\"email\":\"a@example.com\",\"reason\":\"bounce\",\"source\":\"manual\",\"created_at\":\"t\"}");
        try (ApexMailClient client = client(http)) {
            Suppressions.Suppression suppression = client.suppressions().add("a@example.com", "bounce");

            assertEquals("/v1/suppressions", http.lastPath);
            Map<String, Object> body = http.lastRequestBodyJson();
            assertEquals("a@example.com", body.get("email"));
            assertEquals("bounce", body.get("reason"));
            assertFalse(body.containsKey("emails"), "emails[] array must never be sent");
            assertEquals("sup_1", suppression.id());
        }
    }

    @Test
    void suppressionBulkSendsEntriesShape() throws Exception {
        RecordingHttpClient http = new RecordingHttpClient(
            "{\"created\":2,\"duplicates\":0,\"invalid\":0}");
        try (ApexMailClient client = client(http)) {
            Suppressions.BulkResponse response =
                client.suppressions().addBulk(List.of("a@example.com", "b@example.com"), "unsubscribe");

            assertEquals("/v1/suppressions/bulk", http.lastPath);
            Map<String, Object> body = http.lastRequestBodyJson();
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> entries = (List<Map<String, Object>>) body.get("entries");
            assertEquals(2, entries.size());
            assertEquals("a@example.com", entries.get(0).get("email"));
            assertEquals(2, response.created());
        }
    }

    // ── F6: domain + analytics endpoints ──────────────────────────────────

    @Test
    void domainCreateSendsNameAndHealthHitsGetById() throws Exception {
        RecordingHttpClient http = new RecordingHttpClient(
            "{\"id\":\"dom_1\",\"name\":\"mail.example.com\",\"status\":\"pending\",\"ses_verified\":false,"
                + "\"spf_verified\":false,\"dkim_verified\":false,\"dmarc_verified\":false,"
                + "\"return_path_verified\":false,\"created_at\":\"t\"}");
        try (ApexMailClient client = client(http)) {
            Domains.Domain domain = client.domains().create("mail.example.com", Map.of("region", "eu-west-1"));

            Map<String, Object> body = http.lastRequestBodyJson();
            assertEquals(1, body.size());
            assertEquals("mail.example.com", body.get("name"));
            assertEquals("mail.example.com", domain.name());

            client.domains().health("dom_1");
            assertEquals("/v1/domains/dom_1", http.lastPath);
        }
    }

    @Test
    void analyticsTypedMethodsHitRealSubpaths() throws Exception {
        RecordingHttpClient http = new RecordingHttpClient("{\"total_sent\":10}");
        try (ApexMailClient client = client(http)) {
            client.analytics().dashboard("2026-01-01", "2026-02-01", null);
            assertEquals("/v1/analytics/dashboard?from=2026-01-01&to=2026-02-01", http.lastPath);

            client.analytics().volume(null, null, "week");
            assertEquals("/v1/analytics/volume?interval=week", http.lastPath);

            client.analytics().deliverability(null, null, null);
            assertTrue(http.lastPath.startsWith("/v1/analytics/deliverability"),
                "unexpected path: " + http.lastPath);

            client.analytics().analyzeSubjectLine("Open me");
            assertEquals("/v1/analytics/subject-line", http.lastPath);
            assertEquals(Map.of("subject", "Open me"), http.lastRequestBodyJson());
        }
    }

    // ── API-key wire shape vs auth.rs ─────────────────────────────────────

    @Test
    void apiKeyCreateAlwaysSendsScopes() throws Exception {
        RecordingHttpClient http = new RecordingHttpClient(
            "{\"id\":\"key_1\",\"key\":\"am_live_x\",\"key_prefix\":\"am_live\",\"name\":\"deploy\","
                + "\"scopes\":[],\"created_at\":\"t\"}");
        try (ApexMailClient client = client(http)) {
            client.apiKeys().create(Map.of("name", "deploy", "expiresAt", "2030-01-01T00:00:00Z"));

            Map<String, Object> body = http.lastRequestBodyJson();
            assertEquals(List.of(), body.get("scopes"));
            assertFalse(body.containsKey("expiresAt"));
        }
    }

    // ── F7: automatic idempotency keys on mutating POSTs ──────────────────

    @Test
    void mutatingPostsCarryAutoIdempotencyKey() throws Exception {
        RecordingHttpClient http = new RecordingHttpClient(
            "{\"id\":\"wh_1\",\"url\":\"u\",\"events\":[\"message.delivered\"],\"status\":\"active\","
                + "\"created_at\":\"t\",\"updated_at\":\"t\"}");
        try (ApexMailClient client = client(http)) {
            client.webhooks().create(Map.of(
                "url", "https://example.com/hook",
                "events", List.of("message.delivered")));

            String key = http.lastRequest.headers().firstValue("X-Idempotency-Key").orElse(null);
            assertNotNull(key, "auto idempotency key expected on webhook create");
            assertFalse(key.isBlank());
        }
    }

    // ── F11: message get parses the flat MessageDetail ────────────────────

    @Test
    void emailGetParsesFlatMessageDetail() throws Exception {
        RecordingHttpClient http = new RecordingHttpClient(
            "{\"data\":{\"id\":\"msg_1\",\"from\":\"sender@example.com\",\"to\":[\"user@example.com\"],"
                + "\"subject\":\"Hi\",\"status\":\"queued\",\"tags\":[\"promo\"],\"metadata\":null,"
                + "\"scheduled_at\":null,\"sent_at\":null,\"created_at\":\"2026-08-29T00:00:00Z\"},\"error\":null}");
        try (ApexMailClient client = client(http)) {
            Emails.EmailDetail detail = client.emails().get("msg_1");
            assertEquals("sender@example.com", detail.from());
            assertEquals(List.of("user@example.com"), detail.to());
            assertEquals("2026-08-29T00:00:00Z", detail.createdAt());
        }
    }

    // ── F3: platform webhook signature (ms timestamps) ────────────────────

    @Test
    void verifyWebhookSignaturePlatformMillisecondVector() {
        // Known vector: HMAC-SHA256("1750000000000." + payload, secret).
        String payload = "{\"test\":true}";
        String secret = "whsec_test";
        String expectedVector = hexHmac(secret, "1750000000000." + payload);
        assertEquals("31d18ff09cab4d0547ab1c518ffc67124406e128598a7ecfa5dbcc520e4996b2", expectedVector);

        long freshMs = System.currentTimeMillis() - 1000;
        String ts = String.valueOf(freshMs);
        String signature = "sha256=" + hexHmac(secret, ts + "." + payload);

        assertTrue(ApexMailClient.verifyWebhookSignature(payload, signature, secret, Duration.ofMinutes(5), ts),
            "fresh millisecond signature must verify with both platform headers");

        assertFalse(ApexMailClient.verifyWebhookSignature(payload, signature, secret, Duration.ofMinutes(5)),
            "sha256= header without a timestamp must be rejected");

        assertFalse(isStaleVector(secret, payload), "stale millisecond timestamp must be rejected");
    }

    private static boolean isStaleVector(String secret, String payload) {
        // 1750000000000 ms = 2025-06-15 — outside the 5-minute window.
        String staleSig = "sha256=" + hexHmac(secret, "1750000000000." + payload);
        return ApexMailClient.verifyWebhookSignature(payload, staleSig, secret, Duration.ofMinutes(5), "1750000000000");
    }

    private static String hexHmac(String secret, String message) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] digest = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (Exception error) {
            throw new IllegalStateException(error);
        }
    }

    // ── Harness ───────────────────────────────────────────────────────────

    private static String flatSendResponse() {
        return "{\"id\":\"msg_1\",\"status\":\"queued\",\"created_at\":\"2026-08-29T00:00:00Z\"}";
    }

    private static ApexMailClient client(RecordingHttpClient http) {
        return new ApexMailClient(
            "am_test_0123456789abcdef",
            "https://api.apexmail.test",
            Duration.ofSeconds(5),
            http);
    }

    /** Records the last request and replies with a canned 200 body. */
    private static final class RecordingHttpClient extends HttpClient {
        private final String responseBody;
        private HttpRequest lastRequest;
        private String lastRequestBody = "";
        private String lastPath;

        private RecordingHttpClient(String responseBody) {
            this.responseBody = responseBody;
        }

        Map<String, Object> lastRequestBodyJson() {
            try {
                return new com.fasterxml.jackson.databind.ObjectMapper().readValue(
                    lastRequestBody, new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {});
            } catch (IOException error) {
                throw new IllegalStateException(error);
            }
        }

        HttpRequest lastRequest() {
            return lastRequest;
        }

        @Override
        public Optional<CookieHandler> cookieHandler() {
            return Optional.empty();
        }

        @Override
        public Optional<Duration> connectTimeout() {
            return Optional.empty();
        }

        @Override
        public Redirect followRedirects() {
            return Redirect.NEVER;
        }

        @Override
        public Optional<ProxySelector> proxy() {
            return Optional.empty();
        }

        @Override
        public SSLContext sslContext() {
            try {
                return SSLContext.getDefault();
            } catch (Exception error) {
                throw new IllegalStateException(error);
            }
        }

        @Override
        public SSLParameters sslParameters() {
            return new SSLParameters();
        }

        @Override
        public Optional<Authenticator> authenticator() {
            return Optional.empty();
        }

        @Override
        public Version version() {
            return Version.HTTP_1_1;
        }

        @Override
        public Optional<Executor> executor() {
            return Optional.empty();
        }

        @Override
        public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> bodyHandler) throws IOException {
            lastRequest = request;
            lastPath = request.uri().getRawPath() + (request.uri().getRawQuery() != null ? "?" + request.uri().getRawQuery() : "");
            lastRequestBody = readRequestBody(request);
            return buildResponse(request, bodyHandler);
        }

        @Override
        public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request, HttpResponse.BodyHandler<T> bodyHandler) {
            try {
                return CompletableFuture.completedFuture(send(request, bodyHandler));
            } catch (IOException error) {
                return CompletableFuture.failedFuture(error);
            }
        }

        @Override
        public <T> CompletableFuture<HttpResponse<T>> sendAsync(
            HttpRequest request, HttpResponse.BodyHandler<T> bodyHandler, HttpResponse.PushPromiseHandler<T> pushPromiseHandler) {
            return sendAsync(request, bodyHandler);
        }

        private static String readRequestBody(HttpRequest request) {
            HttpRequest.BodyPublisher bodyPublisher = request.bodyPublisher().orElse(HttpRequest.BodyPublishers.noBody());
            BodyCollector collector = new BodyCollector();
            bodyPublisher.subscribe(collector);
            return collector.await();
        }

        private <T> HttpResponse<T> buildResponse(HttpRequest request, HttpResponse.BodyHandler<T> bodyHandler) {
            HttpResponse.ResponseInfo responseInfo = new HttpResponse.ResponseInfo() {
                @Override
                public int statusCode() {
                    return 200;
                }

                @Override
                public HttpHeaders headers() {
                    return HttpHeaders.of(Map.of(), (left, right) -> true);
                }

                @Override
                public Version version() {
                    return Version.HTTP_1_1;
                }
            };

            HttpResponse.BodySubscriber<T> subscriber = bodyHandler.apply(responseInfo);
            subscriber.onSubscribe(new Flow.Subscription() {
                @Override
                public void request(long n) {
                }

                @Override
                public void cancel() {
                }
            });
            subscriber.onNext(List.of(ByteBuffer.wrap(responseBody.getBytes(StandardCharsets.UTF_8))));
            subscriber.onComplete();
            T body = subscriber.getBody().toCompletableFuture().join();

            return new HttpResponse<>() {
                @Override
                public int statusCode() {
                    return 200;
                }

                @Override
                public HttpRequest request() {
                    return request;
                }

                @Override
                public Optional<HttpResponse<T>> previousResponse() {
                    return Optional.empty();
                }

                @Override
                public HttpHeaders headers() {
                    return HttpHeaders.of(Map.of(), (left, right) -> true);
                }

                @Override
                public Optional<javax.net.ssl.SSLSession> sslSession() {
                    return Optional.empty();
                }

                @Override
                public URI uri() {
                    return request.uri();
                }

                @Override
                public Version version() {
                    return Version.HTTP_1_1;
                }

                @Override
                public T body() {
                    return body;
                }
            };
        }
    }

    private static final class BodyCollector implements Flow.Subscriber<ByteBuffer> {
        private final CompletableFuture<String> body = new CompletableFuture<>();
        private final StringBuilder buffer = new StringBuilder();

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            subscription.request(Long.MAX_VALUE);
        }

        @Override
        public void onNext(ByteBuffer item) {
            buffer.append(StandardCharsets.UTF_8.decode(item.duplicate()));
        }

        @Override
        public void onError(Throwable throwable) {
            body.completeExceptionally(throwable);
        }

        @Override
        public void onComplete() {
            body.complete(buffer.toString());
        }

        String await() {
            return body.join();
        }
    }
}
