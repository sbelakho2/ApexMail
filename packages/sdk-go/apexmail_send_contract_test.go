package apexmail

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── F48: shared send contract — packages/contract/send-contract.json ────────
//
// The SAME fixture file drives the api-server contract tests and every SDK
// serialization suite, so the wire forms the SDK emits can never drift from
// what the API deserializer accepts.

func loadSharedContract(t *testing.T) map[string]any {
	t.Helper()
	path := filepath.Join("..", "contract", "send-contract.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("shared contract fixture missing (%s): %v", path, err)
	}
	var contract map[string]any
	if err := json.Unmarshal(raw, &contract); err != nil {
		t.Fatalf("shared contract fixture is not valid JSON: %v", err)
	}
	return contract
}

func contractCases(t *testing.T, section string) []map[string]any {
	t.Helper()
	contract := loadSharedContract(t)
	raw, err := json.Marshal(contract[section].(map[string]any)["cases"])
	if err != nil {
		t.Fatalf("marshal %s cases: %v", section, err)
	}
	var cases []map[string]any
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("unmarshal %s cases: %v", section, err)
	}
	return cases
}

// buildPriority maps a fixture input {type, value} to the SendPriority a
// caller would construct.
func buildPriority(t *testing.T, input map[string]any) SendPriority {
	t.Helper()
	switch input["type"] {
	case "int":
		level, ok := input["value"].(float64)
		if !ok {
			t.Fatalf("int case with non-number value: %#v", input)
		}
		p, err := PriorityInt(int(level))
		if err != nil {
			t.Fatalf("PriorityInt(%v): %v", level, err)
		}
		return p
	case "named":
		level := input["value"].(string)
		p, err := PriorityNamed(level)
		if err != nil {
			t.Fatalf("PriorityNamed(%q): %v", level, err)
		}
		return p
	default:
		// bool/float inputs have no SendPriority constructor — that IS the
		// contract: the type system refuses them.
		t.Fatalf("fixture input type %v must not be constructible", input["type"])
		return SendPriority{}
	}
}

func TestPriorityContractMatchesSharedFixture(t *testing.T) {
	t.Parallel()
	for _, testCase := range contractCases(t, "priority") {
		description := testCase["description"].(string)
		input := testCase["input"].(map[string]any)

		if valid, _ := testCase["valid"].(bool); !valid {
			// Invalid values must be REJECTED client-side with an error
			// naming the contract.
			var err error
			switch input["type"] {
			case "int":
				_, err = PriorityInt(int(input["value"].(float64)))
			case "named":
				_, err = PriorityNamed(input["value"].(string))
			case "bool", "float":
				// No constructor accepts these shapes at all.
				continue
			}
			if err == nil {
				t.Errorf("case %q: expected a contract error", description)
			} else if !strings.Contains(err.Error(), "priority must be") {
				t.Errorf("case %q: error must name the priority contract, got: %v", description, err)
			}
			continue
		}

		priority := buildPriority(t, input)
		wire, err := json.Marshal(priority)
		if err != nil {
			t.Fatalf("case %q: marshal: %v", description, err)
		}
		var got any
		if err := json.Unmarshal(wire, &got); err != nil {
			t.Fatalf("case %q: unmarshal wire form: %v", description, err)
		}
		expected := testCase["wire"]
		switch expectedValue := expected.(type) {
		case string:
			if got != expectedValue {
				t.Errorf("case %q: wire form must be %q, got %#v", description, expectedValue, got)
			}
		case float64:
			if got != expectedValue {
				t.Errorf("case %q: wire form must be %v, got %#v", description, expectedValue, got)
			}
		}
		if queueLevel := testCase["queue"].(float64); priority.QueueLevel() != int(queueLevel) {
			t.Errorf("case %q: queue level must be %v, got %d", description, queueLevel, priority.QueueLevel())
		}

		// The full send payload carries the same wire form under the
		// documented snake_case field name.
		request := &SendEmailRequest{
			From:     EmailAddress{Email: "hello@example.com"},
			To:       []EmailAddress{{Email: "user@example.com"}},
			Subject:  "Hi",
			Text:     "Hello",
			Priority: priority,
		}
		body, err := json.Marshal(request)
		if err != nil {
			t.Fatalf("case %q: marshal request: %v", description, err)
		}
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("case %q: unmarshal request: %v", description, err)
		}
		if payload["priority"] != got {
			t.Errorf("case %q: request priority must serialize as %#v, got %#v", description, got, payload["priority"])
		}
	}

	// Round-trip: an unset priority is omitted from the wire entirely.
	body, err := json.Marshal(&SendEmailRequest{
		From:    EmailAddress{Email: "hello@example.com"},
		To:      []EmailAddress{{Email: "user@example.com"}},
		Subject: "Hi",
		Text:    "Hello",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var payload map[string]any
	_ = json.Unmarshal(body, &payload)
	if _, present := payload["priority"]; present {
		t.Errorf("unset priority must be omitted, got %s", body)
	}
}

func TestMailboxContractMatchesSharedFixture(t *testing.T) {
	t.Parallel()
	for _, testCase := range contractCases(t, "mailbox") {
		description := testCase["description"].(string)

		// Display-name serialization: a structured address built from the
		// fixture's addr_spec/display_name renders back to the canonical
		// input form.
		if valid, _ := testCase["valid"].(bool); valid {
			expectedDisplay, _ := testCase["display_name"].(string)
			addrSpec := testCase["addr_spec"].(string)
			address := EmailAddress{Email: addrSpec, Name: expectedDisplay}
			serialized := formatEmailAddress(address)
			if expectedDisplay != "" {
				expected := expectedDisplay + " <" + addrSpec + ">"
				if serialized != expected {
					t.Errorf("case %q: display form must round-trip to %q, got %q", description, expected, serialized)
				}
			} else if serialized != addrSpec {
				t.Errorf("case %q: bare form must round-trip to %q, got %q", description, addrSpec, serialized)
			}
		}
	}

	// The named-form wire payload: "Name <addr>" strings on every mailbox
	// field — exactly what the API's structured mailbox parser accepts.
	request := &SendEmailRequest{
		From:     EmailAddress{Email: "ada@example.com", Name: "Ada Lovelace"},
		To:       []EmailAddress{{Email: "bob@example.com", Name: "Bob"}, {Email: "carol@example.com"}},
		CC:       []EmailAddress{{Email: "dave@example.com", Name: "Dave"}},
		ReplyTo:  &EmailAddress{Email: "reply@example.com", Name: "Replies"},
		Subject:  "Named mailboxes",
		HTML:     "<p>hi</p>",
		Priority: PriorityHigh,
	}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload["from"] != "Ada Lovelace <ada@example.com>" {
		t.Errorf("from must preserve the display name, got %#v", payload["from"])
	}
	toList, _ := payload["to"].([]any)
	if len(toList) != 2 || toList[0] != "Bob <bob@example.com>" || toList[1] != "carol@example.com" {
		t.Errorf("to must mix display and bare forms, got %#v", payload["to"])
	}
	ccList, _ := payload["cc"].([]any)
	if len(ccList) != 1 || ccList[0] != "Dave <dave@example.com>" {
		t.Errorf("cc must preserve the display name, got %#v", payload["cc"])
	}
	if payload["reply_to"] != "Replies <reply@example.com>" {
		t.Errorf("reply_to must preserve the display name, got %#v", payload["reply_to"])
	}
}
