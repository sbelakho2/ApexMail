package ee.apexmail;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.FileInputStream;
import java.net.http.HttpClient;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Live-stack contract test (2026-10-06 dogfood SDK fixes).
 *
 * <p>Runs only when {@code APEXMAIL_LIVE_API_KEY} is set, so the normal
 * build stays hermetic:
 *
 * <pre>
 * APEXMAIL_LIVE_API_KEY=am_live_… \
 * APEXMAIL_LIVE_BASE_URL=https://127.0.0.1:8443 \
 * APEXMAIL_LIVE_CA_PEM=/tmp/sdklive/tls/cert.pem \
 *   mvn -o test -Dtest=LiveStackContractTest
 * </pre>
 *
 * <p>Every call goes to the running api-server (the brief's live stack is
 * {@code http://127.0.0.1:8080}; this SDK requires https, so a local
 * TLS-terminating proxy fronts the same server when the CA is supplied).
 * The expectations encode the live response shapes: envelope unwrap of
 * {@code {"data":…,"error":null}}, bare-array lists, flat created
 * resources, {@code Idempotency-Key} replay and typed errors.
 */
final class LiveStackContractTest {

    private static ApexMailClient client;
    private static String senderDomain;

    @BeforeAll
    static void setUp() {
        String apiKey = System.getenv("APEXMAIL_LIVE_API_KEY");
        assumeTrue(apiKey != null && !apiKey.isBlank(),
            "APEXMAIL_LIVE_API_KEY not set — live-stack test skipped");
        String baseUrl = Optional.ofNullable(System.getenv("APEXMAIL_LIVE_BASE_URL"))
            .filter(value -> !value.isBlank())
            .orElse("https://127.0.0.1:8443");
        String caPem = System.getenv("APEXMAIL_LIVE_CA_PEM");
        String domain = Optional.ofNullable(System.getenv("APEXMAIL_LIVE_SENDER_DOMAIN"))
            .filter(value -> !value.isBlank())
            .orElse("sdkfix-live-test.example");

        try {
            HttpClient http = caPem == null || caPem.isBlank()
                ? HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build()
                : trustingClient(caPem);
            client = new ApexMailClient(apiKey, baseUrl, Duration.ofSeconds(30), http);
        } catch (Exception error) {
            throw new IllegalStateException("failed to build the live client", error);
        }
        senderDomain = domain;
    }

    @AfterAll
    static void tearDown() {
        if (client != null) {
            pace();
            client.close();
        }
    }

    private static HttpClient trustingClient(String caPem) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate ca;
        try (FileInputStream in = new FileInputStream(caPem)) {
            ca = (X509Certificate) factory.generateCertificate(in);
        }
        KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
        store.load(null, null);
        store.setCertificateEntry("apexmail-live-ca", ca);
        TrustManagerFactory trustManagers =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagers.init(store);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, trustManagers.getTrustManagers(), new SecureRandom());
        return HttpClient.newBuilder()
            .sslContext(context)
            .connectTimeout(Duration.ofSeconds(10))
            .build();
    }

    private static String unique(String prefix) {
        return prefix + "-" + UUID.randomUUID().toString().substring(0, 8);
    }

    /**
     * Pace the calls (~1 rps): the shared dev stack runs an adaptive
     * DDoS middleware that answers a steady burst from one IP with
     * 429 DDOS_RATE_LIMITED. It is a 5-minute per-IP baseline, so a
     * single-IP synthetic sweep must stay slow and steady.
     * The SDK correctly raises RateLimitError there, but a slow, deliberate
     * contract sweep is what this test wants to exercise.
     */
    private static void pace() {
        try {
            Thread.sleep(900);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    @Test
    void sendUnwrapsEnvelopeAndReplaysIdempotencyKey() {
        pace();
        Emails.SendResponse response = client.emails().send(Map.of(
            "from", "sender@" + senderDomain,
            "to", List.of("rcpt@example.test"),
            "subject", "java live",
            "html", "<p>hi</p>"
        ));
        assertNotNull(response.id());
        assertEquals("queued", response.status());

        String key = UUID.randomUUID().toString();
        Map<String, Object> body = Map.of(
            "from", "sender@" + senderDomain,
            "to", List.of("rcpt@example.test"),
            "subject", "java idem",
            "html", "<p>hi</p>"
        );
        pace();
        Emails.SendResponse first = client.emails().send(
            new Emails.SendRequest(body.get("from"), body.get("to"), "java idem",
                "<p>hi</p>", null, null, null, null, null, null, key));
        pace();
        Emails.SendResponse second = client.emails().send(
            new Emails.SendRequest(body.get("from"), body.get("to"), "java idem",
                "<p>hi</p>", null, null, null, null, null, null, key));
        assertEquals(first.id(), second.id(),
            "the same Idempotency-Key must return the original message");

        pace();
        // Cancel a future-scheduled message (a queued one can be dispatched
        // before the cancel lands) and get the flat MessageDetail shape.
        pace();
        Emails.SendResponse scheduled = client.emails().send(Map.of(
            "from", "sender@" + senderDomain,
            "to", List.of("rcpt@example.test"),
            "subject", "java schedule",
            "html", "<p>hi</p>",
            "scheduled_at", java.time.Instant.now().plusSeconds(3600).toString()
        ));
        assertEquals("cancelled", client.emails().cancel(scheduled.id()).status());
        assertEquals(response.id(), client.emails().get(response.id()).id());

        pace();
        List<Emails.EmailDetail> listed = client.emails().list(Map.of("limit", 2));
        assertNotNull(listed);
        assertTrue(client.getLastResponseMeta().isPresent(),
            "GET /v1/messages must expose the pagination meta");

        pace();
        Emails.BatchResponse batch = client.emails().batch(List.of(Map.of(
            "from", "sender@" + senderDomain,
            "to", List.of("rcpt@example.test"),
            "subject", "java batch",
            "html", "<p>hi</p>"
        )));
        assertEquals(1, batch.accepted());
        assertNotNull(batch.results().get(0).id());
    }

    @Test
    void domainsTemplatesWebhooksSuppressionsEventsAndAnalytics() {
        pace();
        List<Domains.Domain> domains = client.domains().list();
        assertFalse(domains.isEmpty(), "the live tenant must have at least one domain");

        pace();
        Domains.Domain created = client.domains().create(unique("java") + ".example");
        assertNotNull(created.id());
        assertEquals(created.id(), client.domains().get(created.id()).id());
        assertNotNull(client.domains().verify(created.id()));
        pace();
        client.domains().delete(created.id());

        pace();
        Templates.Template template = client.templates().create(Map.of(
            "name", unique("java-tpl"),
            "subject", "Hi",
            "html_body", "<p>{{name}}</p>"
        ));
        assertNotNull(template.id());
        assertTrue(client.templates().render(template.id(), Map.of("name", "Ada"))
            .html().contains("Ada"));
        assertTrue(client.templates().update(template.id(), Map.of("name", unique("java-tpl")))
            .version() >= 1);
        assertNotNull(client.templates().duplicate(template.id()).id());
        assertNotNull(client.templates().rollback(template.id(), 1).id());

        pace();
        Webhooks.Webhook webhook = client.webhooks().create(Map.of(
            "url", "https://example.com/" + unique("java-hook"),
            "events", List.of("message.delivered")
        ));
        assertNotNull(webhook.id());
        assertNotNull(webhook.secret());
        assertEquals(webhook.id(), client.webhooks().get(webhook.id()).id());
        assertEquals("paused", client.webhooks().update(webhook.id(), Map.of("status", "paused")).status());
        assertTrue(client.webhooks().rotateSecret(webhook.id()).secret().startsWith("whsec_"));
        assertNotNull(client.webhooks().test(webhook.id()));
        pace();
        client.webhooks().delete(webhook.id());

        pace();
        Suppressions.Suppression suppression =
            client.suppressions().add(unique("java") + "@example.test", "manual");
        assertNotNull(suppression.id());
        assertFalse(client.suppressions().check(unique("java-none") + "@example.test").suppressed());
        assertEquals(1, client.suppressions().bulk(List.of(Map.of(
            "email", unique("java-bulk") + "@example.test",
            "reason", "manual"
        ))).created());
        pace();
        client.suppressions().delete(suppression.id());

        pace();
        List<Events.Event> events = client.events().list(Map.of("limit", 3));
        assertFalse(events.isEmpty());
        assertTrue(((Number) client.events().stats(Map.of()).get("total")).intValue() >= 0);
        assertNotNull(client.events().timeseries(Map.of()));
        assertEquals(events.get(0).id(), client.events().get(events.get(0).id()).id());
        assertFalse(client.events().getByMessage(events.get(0).messageId()).isEmpty());

        pace();
        assertTrue(client.analytics().dashboard(null, null, null).containsKey("total_sent"));
        assertNotNull(client.analytics().volume(null, null, null));
        assertNotNull(client.analytics().engagement(null, null, null));
        assertTrue(client.analytics().deliverability(null, null, null).containsKey("delivery_rate"));
        assertTrue(client.analytics().analyzeSubjectLine("Hello there").containsKey("score"));
        assertTrue(List.of("processing", "completed")
            .contains(client.analytics().export(null, null, "json").get("status")));
    }

    @Test
    void apiKeysAndErrorTyping() {
        pace();
        Map<String, Object> key = client.apiKeys().create(Map.of(
            "name", unique("java-key"),
            "scopes", List.of("events:read")
        ));
        assertTrue(String.valueOf(key.get("key")).startsWith("am_"));
        assertFalse(client.apiKeys().list().isEmpty());
        pace();
        client.apiKeys().revoke(String.valueOf(key.get("id")));

        NotFoundException notFound = assertThrows(NotFoundException.class,
            () -> client.emails().get("no-such-message-" + UUID.randomUUID()));
        assertEquals(404, notFound.getStatusCode());

        // A malformed query parameter is answered by the server with a
        // PLAIN-TEXT 400 (axum QueryRejection) — it must still raise a typed
        // validation error, never be swallowed.
        ApexMailException badRequest = assertThrows(ApexMailException.class, () -> client.request(
            "GET", "/v1/messages?limit=not-a-number", null, Map.class));
        assertEquals(400, badRequest.getStatusCode());
        assertNotNull(badRequest.getCode());
    }
}
