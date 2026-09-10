package ee.apexmail;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * F48 shared send contract (packages/contract/send-contract.json): the SAME
 * fixture file drives the api-server contract tests and every SDK
 * serialization suite, so the wire forms this SDK emits can never drift
 * from what the API deserializer accepts.
 */
class SendContractFixtureTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    private static Map<String, Object> contract() throws Exception {
        return JSON.readValue(
            Path.of("..", "contract", "send-contract.json").toFile(),
            Map.class);
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> cases(String section) throws Exception {
        return (List<Map<String, Object>>) ((Map<String, Object>) contract().get(section)).get("cases");
    }

    private static Object buildPriority(Map<String, Object> input) {
        switch ((String) input.get("type")) {
            case "int": return (int) (double) ((Number) input.get("value")).doubleValue();
            case "named": return (String) input.get("value");
            default:
                // bool/float fixture inputs have no acceptable Java input
                // shape — the SDK must refuse them outright.
                return input.get("value");
        }
    }

    @Test
    void priorityWireFormsMatchTheSharedFixture() throws Exception {
        for (Map<String, Object> testCase : cases("priority")) {
            String description = (String) testCase.get("description");
            Map<String, Object> input = (Map<String, Object>) testCase.get("input");
            Object raw = buildPriority(input);

            if (Boolean.TRUE.equals(testCase.get("valid"))) {
                Object normalized = Emails.normalizePriority(raw);
                assertEquals(testCase.get("wire"), normalized,
                    "case '" + description + "' must serialize to the contract wire form");
            } else {
                IllegalArgumentException error = assertThrows(
                    IllegalArgumentException.class,
                    () -> Emails.normalizePriority(raw),
                    "case '" + description + "' must be rejected client-side");
                assertTrue(error.getMessage().contains("priority must be"),
                    "case '" + description + "' error must name the contract: " + error.getMessage());
            }
        }

        // Named levels are canonicalized case-insensitively; integers stay
        // integers (the API accepts JSON numbers, not numeric strings).
        assertEquals("high", Emails.normalizePriority("HIGH"));
        assertEquals(7, ((Number) Emails.normalizePriority(7)).intValue());
        assertThrows(IllegalArgumentException.class, () -> Emails.normalizePriority("7"));
        assertThrows(IllegalArgumentException.class, () -> Emails.normalizePriority(4.5));
        assertThrows(IllegalArgumentException.class, () -> Emails.normalizePriority(true));
    }

    @Test
    void priorityReachesTheWireInTheContractForm() throws Exception {
        PayloadContractTest.RecordingHttpClient http = new PayloadContractTest.RecordingHttpClient(
            "{\"id\":\"m\",\"status\":\"queued\",\"created_at\":\"t\"}");
        try (ApexMailClient client = PayloadContractTest.client(http)) {
            for (Map<String, Object> testCase : cases("priority")) {
                if (!Boolean.TRUE.equals(testCase.get("valid"))) {
                    continue;
                }
                Map<String, Object> input = (Map<String, Object>) testCase.get("input");
                Map<String, Object> params = new HashMap<>();
                params.put("from", "hello@example.com");
                params.put("to", "user@example.com");
                params.put("subject", "Hi");
                params.put("text", "Hello");
                params.put("priority", buildPriority(input));
                client.emails().send(params);

                Map<String, Object> body = http.lastRequestBodyJson();
                Object wire = body.get("priority");
                if (wire instanceof Number number) {
                    assertEquals(((Number) testCase.get("wire")).doubleValue(), number.doubleValue(),
                        "case '" + testCase.get("description") + "' must serialize the contract integer");
                } else {
                    assertEquals(testCase.get("wire"), wire,
                        "case '" + testCase.get("description") + "' must serialize the contract named level");
                }
            }
        }
    }

    @Test
    void mailboxFormsMatchTheSharedFixture() throws Exception {
        for (Map<String, Object> testCase : cases("mailbox")) {
            String input = (String) testCase.get("input");
            if (Boolean.TRUE.equals(testCase.get("valid"))) {
                // The bare addr-spec is what client-side validation checks.
                assertEquals(testCase.get("addr_spec"), Emails.bareAddress(input),
                    "case '" + testCase.get("description") + "' must extract the bare addr-spec");
            }
        }

        // Structured {email, name} inputs serialize to the same RFC 5322
        // display form the API's mailbox parser accepts (F48).
        PayloadContractTest.RecordingHttpClient http = new PayloadContractTest.RecordingHttpClient(
            "{\"id\":\"m\",\"status\":\"queued\",\"created_at\":\"t\"}");
        try (ApexMailClient client = PayloadContractTest.client(http)) {
            client.emails().send(new Emails.SendRequest(
                Map.of("email", "ada@example.com", "name", "Ada Lovelace"),
                List.of(Map.of("email", "bob@example.com", "name", "Bob"), "carol@example.com"),
                "Named mailboxes",
                null,
                "<p>hi</p>",
                null, null, null, null,
                Map.of("email", "reply@example.com", "name", "Replies"),
                null, null, null, null, null, null, null));
            Map<String, Object> body = http.lastRequestBodyJson();
            assertEquals("Ada Lovelace <ada@example.com>", body.get("from"));
            assertEquals(List.of("Bob <bob@example.com>", "carol@example.com"), body.get("to"));
            assertEquals("Replies <reply@example.com>", body.get("reply_to"));
            assertFalse(body.containsKey("name"));
        }
    }
}
