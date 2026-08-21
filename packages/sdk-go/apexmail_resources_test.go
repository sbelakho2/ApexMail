package apexmail

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientExposesAdvancedResources(t *testing.T) {
	t.Parallel()

	client, err := New("am_live_1234567890abcdef", Config{BaseURL: "https://api.example.test"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	if client.Analytics == nil {
		t.Fatal("expected Analytics resource")
	}
	if client.APIKeys == nil {
		t.Fatal("expected APIKeys resource")
	}
}

func TestAPIKeysCreateUsesAuthEndpoint(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/auth/api-keys" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if payload["name"] != "Deploy key" {
			t.Fatalf("unexpected payload: %#v", payload)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"apiKey":{"id":"key_123"}}`))
	}))
	defer server.Close()

	client, err := New("am_live_1234567890abcdef", Config{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	response, err := client.APIKeys.Create(context.Background(), &CreateAPIKeyRequest{Name: "Deploy key"})
	if err != nil {
		t.Fatalf("create api key: %v", err)
	}
	if response["apiKey"] == nil {
		t.Fatalf("unexpected response: %#v", response)
	}
}

func TestAnalyticsGetBuildsQuery(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/v1/analytics" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("groupBy") != "day" || r.URL.Query().Get("tag") != "welcome" {
			t.Fatalf("unexpected query: %s", r.URL.RawQuery)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"stats":{"sent":10}}`))
	}))
	defer server.Close()

	client, err := New("am_live_1234567890abcdef", Config{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	response, err := client.Analytics.Get(context.Background(), AnalyticsOptions{From: "2026-01-01", To: "2026-01-31", GroupBy: "day", Tag: "welcome"})
	if err != nil {
		t.Fatalf("get analytics: %v", err)
	}
	if response["stats"] == nil {
		t.Fatalf("unexpected response: %#v", response)
	}
}
