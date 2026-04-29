package apexmail

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSuppressionsCheckUsesPathEndpoint(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/v1/suppressions/check/bad@example.com" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.RawQuery != "" {
			t.Fatalf("expected no query string, got %q", r.URL.RawQuery)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"suppressed":true,"reason":"bounce"}`))
	}))
	defer server.Close()

	client := New("am_live_1234567890abcdef", Config{
		BaseURL:    server.URL,
		HTTPClient: server.Client(),
	})

	resp, err := client.Suppressions.Check(context.Background(), "bad@example.com")
	if err != nil {
		t.Fatalf("check suppression: %v", err)
	}
	if !resp.Suppressed || resp.Reason != "bounce" {
		t.Fatalf("unexpected response: %#v", resp)
	}
}