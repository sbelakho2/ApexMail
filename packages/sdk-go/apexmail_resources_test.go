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

func TestAnalyticsDashboardUsesRealSubpath(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		// The API exposes typed subpaths only — GET /v1/analytics does not exist.
		if r.URL.Path != "/v1/analytics/dashboard" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		// AnalyticsQuery accepts exactly {from, to, interval}.
		if r.URL.Query().Get("from") != "2026-01-01" || r.URL.Query().Get("to") != "2026-01-31" || r.URL.Query().Get("interval") != "day" {
			t.Fatalf("unexpected query: %s", r.URL.RawQuery)
		}
		for _, unsupported := range []string{"groupBy", "tag", "domain"} {
			if r.URL.Query().Get(unsupported) != "" {
				t.Fatalf("unsupported query parameter %q sent: %s", unsupported, r.URL.RawQuery)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"total_sent":10,"delivery_rate":1.0}}`))
	}))
	defer server.Close()

	client, err := New("am_live_1234567890abcdef", Config{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	response, err := client.Analytics.Dashboard(context.Background(), AnalyticsOptions{From: "2026-01-01", To: "2026-01-31", Interval: "day"})
	if err != nil {
		t.Fatalf("dashboard analytics: %v", err)
	}
	if response["total_sent"] == nil {
		t.Fatalf("unexpected response: %#v", response)
	}
}

func TestAnalyticsGetDeprecatedAliasHitsDashboard(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/analytics/dashboard" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("interval") != "day" {
			t.Fatalf("groupBy must map to interval, got query: %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"total_sent":0}}`))
	}))
	defer server.Close()

	client, err := New("am_live_1234567890abcdef", Config{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	if _, err := client.Analytics.Get(context.Background(), AnalyticsOptions{From: "2026-01-01", To: "2026-01-31", GroupBy: "day", Tag: "welcome"}); err != nil {
		t.Fatalf("get analytics alias: %v", err)
	}
}
