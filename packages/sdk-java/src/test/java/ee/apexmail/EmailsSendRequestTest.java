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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.Flow;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EmailsSendRequestTest {
    @Test
    void typedSendRequestSerializesEveryAcceptedOption() {
        CapturingHttpClient httpClient = new CapturingHttpClient(successResponse());

        try (ApexMailClient client = new ApexMailClient(
            "am_test_0123456789abcdef",
            "https://api.apexmail.ee",
            Duration.ofSeconds(5),
            httpClient
        )) {
            Emails.SendResponse response = client.emails().send(new Emails.SendRequest(
                "hello@example.com",
                "user@example.com",
                "Scheduled hello",
                "<p>Hello</p>",
                null,
                null,
                null,
                null,
                "support@example.com",
                "2026-05-01T09:00:00Z",
                "idem_typed"
            ));

            // F48: the accepted replyTo option reaches the wire as snake_case
            // reply_to; scheduled_at is snake_case.
            assertTrue(httpClient.lastRequestBody().contains("\"reply_to\":\"support@example.com\""));
            assertFalse(httpClient.lastRequestBody().contains("replyTo"));
            assertTrue(httpClient.lastRequestBody().contains("\"scheduled_at\":\"2026-05-01T09:00:00Z\""));
            assertTrue(httpClient.lastRequestBody().contains("\"from\":\"hello@example.com\""));
            assertTrue(httpClient.lastRequestBody().contains("\"to\":[\"user@example.com\"]"));
            assertEquals("idem_typed", httpClient.lastRequest().headers().firstValue("Idempotency-Key").orElseThrow());
        }
    }

    @Test
    void mapSendSerializesEveryAcceptedOption() {
        CapturingHttpClient httpClient = new CapturingHttpClient(successResponse());

        Map<String, Object> params = new HashMap<>();
        params.put("from", "hello@example.com");
        params.put("to", "user@example.com");
        params.put("subject", "Scheduled hello");
        params.put("html", "<p>Hello</p>");
        params.put("replyTo", "support@example.com");
        params.put("scheduledAt", "2026-05-01T09:00:00Z");
        params.put("idempotencyKey", "idem_map");

        try (ApexMailClient client = new ApexMailClient(
            "am_test_0123456789abcdef",
            "https://api.apexmail.ee",
            Duration.ofSeconds(5),
            httpClient
        )) {
            client.emails().send(params);

            // F48: reply_to is serialized snake_case, never dropped.
            assertTrue(httpClient.lastRequestBody().contains("\"reply_to\":\"support@example.com\""));
            assertFalse(httpClient.lastRequestBody().contains("replyTo"));
            assertFalse(httpClient.lastRequestBody().contains("scheduledAt"));
            assertTrue(httpClient.lastRequestBody().contains("\"scheduled_at\":\"2026-05-01T09:00:00Z\""));
            assertTrue(httpClient.lastRequestBody().contains("\"from\":\"hello@example.com\""));
            assertEquals("idem_map", httpClient.lastRequest().headers().firstValue("Idempotency-Key").orElseThrow());
        }
    }

    private static String successResponse() {
        return """
            {"message":{"id":"msg_123","messageId":"smtp_123","status":"queued","recipients":1,"scheduledAt":"2026-05-01T09:00:00Z","createdAt":"2026-04-29T12:00:00Z"}}
            """;
    }

    private static Map<String, Object> params(Object... keyValues) {
        Map<String, Object> map = new HashMap<>();
        for (int i = 0; i < keyValues.length; i += 2) {
            map.put((String) keyValues[i], keyValues[i + 1]);
        }
        return map;
    }

    /** Template sends (docs/api/endpoints/messages.md): template_id names a
     *  stored template that supplies subject/html/text, rendered with
     *  template_data — a template-only send omits the content keys. */
    @Test
    void templateOnlySendSerializesTemplateFieldsAndOmitsEmptyContent() {
        CapturingHttpClient httpClient = new CapturingHttpClient(successResponse());

        try (ApexMailClient client = new ApexMailClient(
            "am_test_0123456789abcdef",
            "https://api.apexmail.ee",
            Duration.ofSeconds(5),
            httpClient
        )) {
            client.emails().send(params(
                "from", "hello@example.com",
                "to", "user@example.com",
                "template_id", "tpl_1",
                "template_data", Map.of("name", "Ada")
            ));

            String body = httpClient.lastRequestBody();
            assertTrue(body.contains("\"template_id\":\"tpl_1\""), body);
            assertTrue(body.contains("\"template_data\":{\"name\":\"Ada\"}"), body);
            assertFalse(body.contains("\"subject\""), body);
            assertFalse(body.contains("\"html\""), body);
            assertFalse(body.contains("\"text\""), body);

            // The typed SendRequest constructor also allows template-only sends.
            client.emails().send(new Emails.SendRequest(
                "hello@example.com",
                "user@example.com",
                null,
                null,
                null,
                "tpl_2",
                null,
                null,
                null,
                null,
                null
            ));
            assertTrue(httpClient.lastRequestBody().contains("\"template_id\":\"tpl_2\""),
                httpClient.lastRequestBody());
        }
    }

    /** Shapes the server refuses (template_data without a template_id, or a
     *  non-object template_data) are refused client-side before any request. */
    @Test
    void templateShapeViolationsAreRefusedClientSide() {
        CapturingHttpClient httpClient = new CapturingHttpClient(successResponse());

        try (ApexMailClient client = new ApexMailClient(
            "am_test_0123456789abcdef",
            "https://api.apexmail.ee",
            Duration.ofSeconds(5),
            httpClient
        )) {
            assertThrows(IllegalArgumentException.class, () -> client.emails().send(params(
                "from", "hello@example.com",
                "to", "user@example.com",
                "subject", "Hi",
                "text", "body",
                "template_data", Map.of("name", "Ada")
            )));
            assertThrows(IllegalArgumentException.class, () -> client.emails().send(params(
                "from", "hello@example.com",
                "to", "user@example.com",
                "template_id", "tpl_1",
                "template_data", List.of("not", "an", "object")
            )));
            assertThrows(IllegalArgumentException.class, () -> client.emails().send(params(
                "from", "hello@example.com",
                "to", "user@example.com",
                "text", "body"
            )));
            assertNull(httpClient.lastRequest(), "refused shapes must not reach the wire");
        }
    }

    private static final class CapturingHttpClient extends HttpClient {
        private final String responseBody;
        private HttpRequest lastRequest;
        private String lastRequestBody = "";

        private CapturingHttpClient(String responseBody) {
            this.responseBody = responseBody;
        }

        HttpRequest lastRequest() {
            return lastRequest;
        }

        String lastRequestBody() {
            return lastRequestBody;
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
        public Optional<Executor> executor() {
            return Optional.empty();
        }

        @Override
        public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler) throws IOException {
            lastRequest = request;
            lastRequestBody = readRequestBody(request);
            return buildResponse(request, responseBodyHandler);
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

        private <T> HttpResponse<T> buildResponse(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler) {
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

            HttpResponse.BodySubscriber<T> subscriber = responseBodyHandler.apply(responseInfo);
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
                public T body() {
                    return body;
                }

                @Override
                public Optional<SSLSession> sslSession() {
                    return Optional.empty();
                }

                @Override
                public java.net.URI uri() {
                    return request.uri();
                }

                @Override
                public Version version() {
                    return Version.HTTP_1_1;
                }
            };
        }

        private static String readRequestBody(HttpRequest request) {
            HttpRequest.BodyPublisher bodyPublisher = request.bodyPublisher().orElse(HttpRequest.BodyPublishers.noBody());
            BodyCollector collector = new BodyCollector();
            bodyPublisher.subscribe(collector);
            return collector.await();
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