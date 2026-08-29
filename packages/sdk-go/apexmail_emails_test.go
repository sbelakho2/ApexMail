package apexmail

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEmailsCancelUsesCancelEndpoint(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/messages/msg_123/cancel" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if len(body) != 0 {
			t.Fatalf("expected empty body, got %q", string(body))
		}

		w.Header().Set("Content-Type", "application/json")
		// Real MessageResponse shape: snake_case created_at.
		_, _ = w.Write([]byte(`{"id":"msg_123","status":"cancelled","created_at":"2026-04-27T12:00:00Z"}`))
	}))
	defer server.Close()

	client, err := New("am_live_1234567890abcdef", Config{
		BaseURL:    server.URL,
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	resp, err := client.Emails.Cancel(context.Background(), "msg_123")
	if err != nil {
		t.Fatalf("cancel email: %v", err)
	}
	if resp.ID != "msg_123" || resp.Status != "cancelled" {
		t.Fatalf("unexpected response: %#v", resp)
	}
	if resp.CreatedAt != "2026-04-27T12:00:00Z" {
		t.Fatalf("expected CreatedAt to deserialize, got %#v", resp)
	}
}

func TestEmailsCancelRequiresID(t *testing.T) {
	t.Parallel()

	client, err := New("am_live_1234567890abcdef")
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	resp, err := client.Emails.Cancel(context.Background(), "   ")
	if err == nil {
		t.Fatalf("expected error, got response %#v", resp)
	}
}