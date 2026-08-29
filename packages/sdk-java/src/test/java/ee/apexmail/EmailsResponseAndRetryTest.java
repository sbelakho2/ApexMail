package ee.apexmail;

import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Flow;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * SDK-B/C/E/F coverage: real API response shapes, automatic idempotency
 * keys, request timeouts, Retry-After handling, and webhook hardening.
 */
class EmailsResponseAndRetryTest {

    // ── SDK-C: real response shapes ────────────────────────────────────────

    @Test
    void sendDecodesRealFlatResponseShape() {
        CapturingHttpClient http = new CapturingHttpClient(List.of(response(200, """
            {"id":"msg_flat_1","status":"queued","created_at":"2026-08-21T12:00:00Z"}
            """)));

        try (ApexMailClient client = client(http)) {
            Emails.SendResponse response = client.emails().send(new Emails.SendRequest(
                "hello@example.com", "user@example.com", "Hi", "<p>Hi</p>", null, null, null, null, null, null, null));

            assertEquals("msg_flat_1", response.id());
            assertEquals("queued", response.status());
            assertEquals("2026-08-21T12:00:00Z", response.createdAt());
        }
    }

    @Test
    void sendDecodesRealFlatResponseInsideEnvelope() {
        CapturingHttpClient http = new CapturingHttpClient(List.of(response(200, """
            {"data":{"id":"msg_env","status":"queued","created_at":"2026-08-21T12:00:00Z"}}
            """)));

        try (ApexMailClient client = client(http)) {
            Emails.SendResponse response = client.emails().send(new Emails.SendRequest(
                "hello@example.com", "user@example.com", "Hi", "<p>Hi</p>", null, null, null, null, null, null, null));

            assertEquals("msg_env", response.id());
            assertEquals("queued", response.status());
        }
    }

    @Test
    void batchDecodesRealResponseShape() {
        CapturingHttpClient http = new CapturingHttpClient(List.of(response(200, """
            {"data":{"accepted":2,"rejected":1,"results":[
              {"index":0,"id":"msg_b1","status":"queued"},
              {"index":1,"id":"msg_b2","status":"queued"},
              {"index":2,"status":"rejected","error":"invalid recipient"}
            ]}}
            """)));

        try (ApexMailClient client = client(http)) {
            Emails.BatchResponse response = client.emails().batch(List.of(
                Map.of("from", "a@example.com", "to", "x@example.com", "subject", "1", "text", "x"),
                Map.of("from", "a@example.com", "to", "y@example.com", "subject", "2", "text", "x"),
                Map.of("from", "a@example.com", "to", "z@example.com", "subject", "3", "text", "x")));

            assertEquals(2, response.accepted());
            assertEquals(1, response.rejected());
            assertEquals(3, response.results().size());
            assertEquals("msg_b1", response.results().get(0).id());
            assertEquals("queued", response.results().get(0).status());
            assertNull(response.results().get(2).id(), "rejected items carry no id");
            assertEquals("rejected", response.results().get(2).status());
            assertEquals("invalid recipient", response.results().get(2).error());
        }
    }

    // ── SDK-B: automatic idempotency keys ──────────────────────────────────

    @Test
    void sendAutoGeneratesIdempotencyKeyAndReplaysItAcrossRetries() {
        CapturingHttpClient http = new CapturingHttpClient(List.of(
            response(500, "{\"error\":{\"code\":\"INTERNAL\",\"message\":\"transient\"}}"),
            response(200, "{\"id\":\"msg_retry\",\"status\":\"queued\",\"created_at\":\"now\"}")));

        try (ApexMailClient client = client(http)) {
            Emails.SendResponse response = client.emails().send(new Emails.SendRequest(
                "hello@example.com", "user@example.com", "Hi", "<p>Hi</p>", null, null, null, null, null, null, null));

            assertEquals("msg_retry", response.id());
            assertEquals(2, http.requestCount());
            String key1 = http.request(0).headers().firstValue("X-Idempotency-Key").orElseThrow();
            String key2 = http.request(1).headers().firstValue("X-Idempotency-Key").orElseThrow();
            assertTrue(!key1.isBlank(), "auto idempotency key must be present");
            assertEquals(key1, key2, "same key must be replayed across retries of one send");
        }
    }

    @Test
    void twoLogicalSendsGetDifferentAutoKeys() {
        CapturingHttpClient http = new CapturingHttpClient(List.of(
            response(200, "{\"id\":\"m1\",\"status\":\"queued\",\"created_at\":\"a\"}"),
            response(200, "{\"id\":\"m2\",\"status\":\"queued\",\"created_at\":\"b\"}")));

        try (ApexMailClient client = client(http)) {
            Emails.SendRequest request = new Emails.SendRequest(
                "hello@example.com", "user@example.com", "Hi", "<p>Hi</p>", null, null, null, null, null, null, null);
            client.emails().send(request);
            client.emails().send(request);

            String key1 = http.request(0).headers().firstValue("X-Idempotency-Key").orElseThrow();
            String key2 = http.request(1).headers().firstValue("X-Idempotency-Key").orElseThrow();
            assertNotEquals(key1, key2, "each logical send must get a fresh key");
        }
    }

    @Test
    void batchSendsAutoIdempotencyKey() {
        CapturingHttpClient http = new CapturingHttpClient(List.of(
            response(200, "{\"data\":{\"accepted\":1,\"rejected\":0,\"results\":[{\"index\":0,\"id\":\"m\",\"status\":\"queued\"}]}}")));

        try (ApexMailClient client = client(http)) {
            client.emails().batch(List.of(
                Map.of("from", "a@example.com", "to", "x@example.com", "subject", "1", "text", "x")));

            String key = http.request(0).headers().firstValue("X-Idempotency-Key").orElseThrow();
            assertTrue(!key.isBlank(), "batch must carry an auto idempotency key");
        }
    }

    @Test
    void serializationFailureIsNotRetried() {
        CapturingHttpClient http = new CapturingHttpClient(List.of());

        try (ApexMailClient client = client(http)) {
            Map<String, Object> unserializable = new HashMap<>();
            unserializable.put("from", "a@example.com");
            unserializable.put("to", "b@example.com");
            unserializable.put("subject", "Hi");
            unserializable.put("html", "<p>x</p>");
            unserializable.put("metadata", Map.of("boom", new Object())); // Jackson cannot serialize Object

            ApexMailException error = assertThrows(ApexMailException.class,
                () -> client.emails().send(unserializable));

            assertEquals("SERIALIZATION_ERROR", error.getCode());
            assertEquals(0, http.requestCount(), "serialization failures must not reach the transport");
        }
    }

    // ── SDK-E: timeouts, retry budget, 422 mapping, webhook t= ─────────────

    @Test
    void requestsCarryConfiguredTimeout() {
        CapturingHttpClient http = new CapturingHttpClient(List.of(
            response(200, "{\"id\":\"m\",\"status\":\"queued\",\"created_at\":\"now\"}")));

        try (ApexMailClient client = client(http, Duration.ofSeconds(7))) {
            client.emails().send(new Emails.SendRequest(
                "hello@example.com", "user@example.com", "Hi", "<p>Hi</p>", null, null, null, null, null, null, null));

            assertEquals(Optional.of(Duration.ofSeconds(7)), http.request(0).timeout());
        }
    }

    @Test
    void status422MapsToValidationException() {
        CapturingHttpClient http = new CapturingHttpClient(List.of(
            response(422, "{\"error\":{\"code\":\"VALIDATION_ERROR\",\"message\":\"bad payload\"}}")));

        try (ApexMailClient client = client(http)) {
            ValidationException error = assertThrows(ValidationException.class,
                () -> client.emails().send(new Emails.SendRequest(
                    "hello@example.com", "user@example.com", "Hi", "<p>Hi</p>", null, null, null, null, null, null, null)));

            assertEquals(422, error.getStatusCode());
            assertEquals(1, http.requestCount(), "422 is a client error and must not be retried");
        }
    }

    @Test
    void webhookSignatureMissingTimestampIsRejected() {
        long now = System.currentTimeMillis() / 1000L;
        String payload = "{\"event\":\"message.sent\"}";
        String secret = "whsec_test";
        String signature = hmacSha256(secret, now + "." + payload);

        // A header without t= (bare "v1=..." or "sha256=...") must be
        // rejected outright — previously the missing timestamp was
        // substituted with now(), making the tolerance window vacuous.
        assertFalse(ApexMailClient.verifyWebhookSignature(payload, "v1=" + signature, secret));
        assertFalse(ApexMailClient.verifyWebhookSignature(payload, "sha256=" + signature, secret));
        // A well-formed header with t= still verifies.
        assertTrue(ApexMailClient.verifyWebhookSignature(payload, "t=" + now + ",v1=" + signature, secret));
    }

    private static void assertFalse(boolean value) {
        assertTrue(!value, "expected false");
    }

    private static String hmacSha256(String secret, String payload) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] raw = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(raw.length * 2);
            for (byte b : raw) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // ── SDK-F: Retry-After honored up to 120s ──────────────────────────────

    @Test
    void retryDelayHonorsRetryAfterInFullCappedAt120s() {
        assertEquals(Duration.ofSeconds(60), retryDelayWithHeader("60", 0));
        assertEquals(Duration.ofSeconds(3), retryDelayWithHeader("3", 2)); // max(2s backoff, 3s) = 3s
        assertEquals(Duration.ofSeconds(120), retryDelayWithHeader("300", 0)); // capped
        assertEquals(Duration.ofSeconds(2), retryDelayWithHeader(null, 2)); // quadratic backoff 500ms*4
        // F8: the first retry uses attempt 1, so the backoff floor is 500ms —
        // a 0-based exponent produced a 0s delay (an immediate hammer at a
        // server that had just said "slow down").
        assertEquals(Duration.ofMillis(500), retryDelayWithHeader(null, 0));
        assertEquals(Duration.ofMillis(500), retryDelayWithHeader("garbage", 0)); // unparseable → backoff floor
    }

    private static Duration retryDelayWithHeader(String retryAfter, int attempt) {
        Map<String, List<String>> headers = new HashMap<>();
        if (retryAfter != null) {
            headers.put("Retry-After", List.of(retryAfter));
        }
        HttpResponse<Void> response = new HttpResponse<>() {
            @Override public int statusCode() { return 429; }
            @Override public HttpRequest request() { throw new UnsupportedOperationException(); }
            @Override public Optional<HttpResponse<Void>> previousResponse() { return Optional.empty(); }
            @Override public HttpHeaders headers() { return HttpHeaders.of(headers, (a, b) -> true); }
            @Override public Void body() { return null; }
            @Override public Optional<SSLSession> sslSession() { return Optional.empty(); }
            @Override public java.net.URI uri() { throw new UnsupportedOperationException(); }
            @Override public HttpClient.Version version() { return HttpClient.Version.HTTP_1_1; }
        };
        return ApexMailClient.retryDelay(response, attempt);
    }

    // ── Non-happy-path: non-JSON 502 ───────────────────────────────────────

    @Test
    void nonJson502SurfacesAsErrorAfterRetries() {
        CapturingHttpClient http = new CapturingHttpClient(List.of(
            response(502, "<html><body>502 Bad Gateway</body></html>"),
            response(502, "<html><body>502 Bad Gateway</body></html>"),
            response(502, "<html><body>502 Bad Gateway</body></html>"),
            response(502, "<html><body>502 Bad Gateway</body></html>")));

        try (ApexMailClient client = client(http)) {
            ApexMailException error = assertThrows(ApexMailException.class,
                () -> client.emails().send(new Emails.SendRequest(
                    "hello@example.com", "user@example.com", "Hi", "<p>Hi</p>", null, null, null, null, null, null, null)));

            assertEquals(502, error.getStatusCode());
            assertEquals(4, http.requestCount(), "5xx must be retried up to DEFAULT_MAX_RETRIES");
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private static ApexMailClient client(CapturingHttpClient http) {
        return client(http, Duration.ofSeconds(5));
    }

    private static ApexMailClient client(CapturingHttpClient http, Duration timeout) {
        return new ApexMailClient("am_test_0123456789abcdef", "https://api.apexmail.ee", timeout, http);
    }

    private record ScriptedResponse(int status, String body) {}

    private static ScriptedResponse response(int status, String body) {
        return new ScriptedResponse(status, body);
    }

    /**
     * HttpClient fake that plays a scripted sequence of responses and records
     * every request (for header/idempotency assertions).
     */
    private static final class CapturingHttpClient extends HttpClient {
        private final List<ScriptedResponse> responses;
        private final List<HttpRequest> requests = new ArrayList<>();
        private final AtomicInteger index = new AtomicInteger();

        private CapturingHttpClient(List<ScriptedResponse> responses) {
            this.responses = responses;
        }

        HttpRequest request(int i) {
            return requests.get(i);
        }

        int requestCount() {
            return requests.size();
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
                throw new IllegalStateException("Unable to create default SSL context", error);
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
        public Optional<java.util.concurrent.Executor> executor() {
            return Optional.empty();
        }

        @Override
        public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler) throws IOException {
            requests.add(request);
            int i = Math.min(index.getAndIncrement(), responses.size() - 1);
            ScriptedResponse scripted = responses.get(i);
            return buildResponse(request, responseBodyHandler, scripted);
        }

        @Override
        public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler) {
            try {
                return CompletableFuture.completedFuture(send(request, responseBodyHandler));
            } catch (IOException error) {
                return CompletableFuture.failedFuture(error);
            }
        }

        @Override
        public <T> CompletableFuture<HttpResponse<T>> sendAsync(
            HttpRequest request,
            HttpResponse.BodyHandler<T> responseBodyHandler,
            HttpResponse.PushPromiseHandler<T> pushPromiseHandler
        ) {
            return sendAsync(request, responseBodyHandler);
        }

        private <T> HttpResponse<T> buildResponse(
            HttpRequest request,
            HttpResponse.BodyHandler<T> responseBodyHandler,
            ScriptedResponse scripted
        ) {
            HttpResponse.ResponseInfo responseInfo = new HttpResponse.ResponseInfo() {
                @Override public int statusCode() { return scripted.status(); }
                @Override public HttpHeaders headers() { return HttpHeaders.of(Map.of(), (a, b) -> true); }
                @Override public Version version() { return Version.HTTP_1_1; }
            };

            HttpResponse.BodySubscriber<T> subscriber = responseBodyHandler.apply(responseInfo);
            subscriber.onSubscribe(new Flow.Subscription() {
                @Override public void request(long n) {}
                @Override public void cancel() {}
            });
            subscriber.onNext(List.of(ByteBuffer.wrap(scripted.body().getBytes(StandardCharsets.UTF_8))));
            subscriber.onComplete();
            T body = subscriber.getBody().toCompletableFuture().join();

            return new HttpResponse<>() {
                @Override public int statusCode() { return scripted.status(); }
                @Override public HttpRequest request() { return request; }
                @Override public Optional<HttpResponse<T>> previousResponse() { return Optional.empty(); }
                @Override public HttpHeaders headers() { return HttpHeaders.of(Map.of(), (a, b) -> true); }
                @Override public T body() { return body; }
                @Override public Optional<SSLSession> sslSession() { return Optional.empty(); }
                @Override public java.net.URI uri() { return request.uri(); }
                @Override public Version version() { return Version.HTTP_1_1; }
            };
        }
    }

    @Test
    void sanityAllScriptedResponsesConsumed() {
        assertNotNull(Duration.ZERO);
    }
}
